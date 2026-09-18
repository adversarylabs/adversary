// Package catalogapply turns approved catalog-training rules into local policy
// edits or isolated GitHub pull requests.
package catalogapply

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/doomerlabs/adversary/internal/train/results"
	"github.com/doomerlabs/adversary/internal/train/workspace"
	"gopkg.in/yaml.v3"
)

var safeID = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
var catalogGitMu sync.Mutex

// Apply writes one approved rule into its adversary source and marks the inbox
// row applied. The caller owns any later git commit or pull request.
func Apply(_ context.Context, stateRoot, workspaceRoot string, cfg workspace.Config, id string) error {
	row, err := results.Get(stateRoot, id)
	if err != nil {
		return err
	}
	target, err := applyCandidate(workspaceRoot, cfg, row)
	if err != nil {
		return err
	}
	row.Status = results.StatusApplied
	row.AppliedAt = time.Now().UTC()
	row.AppliedPath = target
	return results.SaveResult(stateRoot, row)
}

// CreatePullRequest writes a candidate in an isolated worktree based on the
// remote default branch, commits it, pushes it, and opens a GitHub pull request.
// It never switches or writes catalog files in the caller's current checkout.
func CreatePullRequest(ctx context.Context, stateRoot, workspaceRoot string, cfg workspace.Config, id string) error {
	return createPullRequest(ctx, stateRoot, workspaceRoot, cfg, id, nil, execCommand, nil)
}

// CreatePullRequestPlanned generates a substantive adversary change in the
// isolated worktree before committing and proposing it.
func CreatePullRequestPlanned(ctx context.Context, stateRoot, workspaceRoot string, cfg workspace.Config, id string, planner ChangePlanner) error {
	return CreatePullRequestPlannedWithProgress(ctx, stateRoot, workspaceRoot, cfg, id, planner, nil)
}

type Progress struct {
	Stage  string `json:"stage"`
	State  string `json:"state"`
	Detail string `json:"detail,omitempty"`
}

type ProgressReporter func(Progress)

func CreatePullRequestPlannedWithProgress(ctx context.Context, stateRoot, workspaceRoot string, cfg workspace.Config, id string, planner ChangePlanner, report ProgressReporter) error {
	return createPullRequest(ctx, stateRoot, workspaceRoot, cfg, id, planner, execCommand, report)
}

// CreatePullRequestPlannedWithProgressAllowOverlap creates a catalog proposal
// after the user explicitly chooses to add a rule despite existing coverage.
func CreatePullRequestPlannedWithProgressAllowOverlap(ctx context.Context, stateRoot, workspaceRoot string, cfg workspace.Config, id string, planner ChangePlanner, report ProgressReporter) error {
	return createPullRequestWithOptions(ctx, stateRoot, workspaceRoot, cfg, id, planner, execCommand, report, true)
}

type commandRunner func(context.Context, string, string, ...string) ([]byte, error)

func execCommand(ctx context.Context, dir, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Dir = dir
	// Version managers commonly expose npm as an absolute launcher whose
	// shebang is /usr/bin/env node. The review UI may not inherit the
	// interactive shell PATH, so keep the resolved launcher's sibling runtime
	// visible to env when executing it.
	if filepath.IsAbs(name) {
		command.Env = prependPath(os.Environ(), filepath.Dir(name))
	}
	return command.CombinedOutput()
}

func prependPath(environment []string, directory string) []string {
	prefix := "PATH="
	for index, entry := range environment {
		if strings.HasPrefix(entry, prefix) {
			copy := append([]string(nil), environment...)
			copy[index] = prefix + directory + string(os.PathListSeparator) + strings.TrimPrefix(entry, prefix)
			return copy
		}
	}
	return append(append([]string(nil), environment...), prefix+directory)
}

func createPullRequest(ctx context.Context, stateRoot, workspaceRoot string, cfg workspace.Config, id string, planner ChangePlanner, run commandRunner, report ProgressReporter) error {
	return createPullRequestWithOptions(ctx, stateRoot, workspaceRoot, cfg, id, planner, run, report, false)
}

func createPullRequestWithOptions(ctx context.Context, stateRoot, workspaceRoot string, cfg workspace.Config, id string, planner ChangePlanner, run commandRunner, report ProgressReporter, allowOverlap bool) error {
	emit := func(stage, state, detail string) {
		if report != nil {
			report(Progress{Stage: stage, State: state, Detail: detail})
		}
	}
	emit("bootstrap", "running", "Preparing an isolated catalog branch")
	row, err := results.Get(stateRoot, id)
	if err != nil {
		return err
	}
	if err := validateCandidate(row); err != nil {
		return err
	}
	gitRootRaw, err := requireCommand(ctx, run, workspaceRoot, "git", "rev-parse", "--show-toplevel")
	if err != nil {
		return fmt.Errorf("catalog workspace is not a Git repository: %w", err)
	}
	gitRoot := strings.TrimSpace(string(gitRootRaw))
	canonicalGitRoot, err := filepath.EvalSymlinks(gitRoot)
	if err != nil {
		return fmt.Errorf("resolve catalog Git root: %w", err)
	}
	canonicalWorkspace, err := filepath.EvalSymlinks(workspaceRoot)
	if err != nil {
		return fmt.Errorf("resolve catalog workspace: %w", err)
	}
	gitRoot = canonicalGitRoot
	workspaceRelative, err := filepath.Rel(gitRoot, canonicalWorkspace)
	if err != nil || workspaceRelative == ".." || strings.HasPrefix(workspaceRelative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("catalog workspace is outside its Git repository")
	}
	catalogGitMu.Lock()
	gitSetupLocked := true
	defer func() {
		if gitSetupLocked {
			catalogGitMu.Unlock()
		}
	}()
	if _, err := requireCommand(ctx, run, gitRoot, "git", "fetch", "origin"); err != nil {
		return fmt.Errorf("refresh catalog default branch: %w", err)
	}
	baseRef, baseBranch, err := remoteDefaultBranch(ctx, run, gitRoot)
	if err != nil {
		return err
	}

	worktree, err := os.MkdirTemp("", "adversary-catalog-pr-*")
	if err != nil {
		return fmt.Errorf("create catalog pull-request workspace: %w", err)
	}
	if err := os.Remove(worktree); err != nil {
		return fmt.Errorf("prepare catalog pull-request workspace: %w", err)
	}
	branch := pullRequestBranch(row)
	added := false
	defer func() {
		catalogGitMu.Lock()
		defer catalogGitMu.Unlock()
		if added {
			_, _ = run(context.Background(), gitRoot, "git", "worktree", "remove", "--force", worktree)
			_, _ = run(context.Background(), gitRoot, "git", "branch", "-D", branch)
		} else {
			_ = os.RemoveAll(worktree)
		}
	}()
	if _, err := requireCommand(ctx, run, gitRoot, "git", "worktree", "add", "--no-track", "-b", branch, worktree, baseRef); err != nil {
		return fmt.Errorf("create isolated catalog branch: %w", err)
	}
	added = true
	catalogGitMu.Unlock()
	gitSetupLocked = false
	emit("bootstrap", "complete", "Isolated branch ready")

	targetWorkspace := filepath.Join(worktree, workspaceRelative)
	worktreeConfig, err := configForWorktree(cfg, canonicalWorkspace, targetWorkspace)
	if err != nil {
		return err
	}
	var target, generatedTitle string
	if planner == nil {
		target, err = applyCandidate(targetWorkspace, worktreeConfig, row)
	} else {
		target, generatedTitle, err = applyPlannedCandidateWithProgressOptionsAndRunner(ctx, targetWorkspace, worktreeConfig, row, planner, report, allowOverlap, run)
	}
	if err != nil {
		return err
	}
	emit("commit", "running", "Committing the reviewed catalog change")
	if _, err := requireCommand(ctx, run, worktree, "git", "add", "-A", "--", ".", ":(glob,exclude)**/node_modules/**", ":(glob,exclude)**/.adversary/**"); err != nil {
		return fmt.Errorf("stage catalog change: %w", err)
	}
	changed, err := requireCommand(ctx, run, worktree, "git", "diff", "--cached", "--name-only")
	if err != nil {
		return fmt.Errorf("inspect catalog change: %w", err)
	}
	if strings.TrimSpace(string(changed)) == "" {
		return fmt.Errorf("candidate %s produced no catalog change", row.ID)
	}
	commitTitle := catalogPullRequestTitle(row, generatedTitle)
	if _, err := requireCommand(ctx, run, worktree, "git", "commit", "-m", commitTitle); err != nil {
		return fmt.Errorf("commit catalog change: %w", err)
	}
	emit("commit", "complete", "Catalog change committed")
	emit("push", "running", "Pushing the isolated catalog branch")
	if _, err := requireCommand(ctx, run, worktree, "git", "push", "origin", "HEAD:refs/heads/"+branch); err != nil {
		return fmt.Errorf("push catalog branch: %w", err)
	}
	emit("push", "complete", "Catalog branch pushed")
	emit("pull_request", "running", "Opening the catalog pull request")
	body := pullRequestBody(row, target, generatedTitle, planner != nil, strings.Contains(filepath.ToSlash(string(changed)), "/package.json"))
	created, err := requireCommand(ctx, run, worktree, "gh", "pr", "create", "--base", baseBranch, "--head", branch, "--title", commitTitle, "--body", body)
	if err != nil {
		return fmt.Errorf("catalog branch %s was pushed, but opening its pull request failed: %w", branch, err)
	}
	prURL := lastURL(string(created))
	if prURL == "" {
		return fmt.Errorf("catalog pull request was created but gh returned no URL")
	}
	relTarget, err := filepath.Rel(worktree, target)
	if err != nil {
		relTarget = target
	}
	row.Status = results.StatusProposed
	row.AppliedAt = time.Now().UTC()
	row.AppliedPath = filepath.ToSlash(relTarget)
	row.Branch = branch
	row.CatalogPRURL = prURL
	if err := results.SaveResult(stateRoot, row); err != nil {
		return fmt.Errorf("pull request created at %s, but its inbox record could not be updated: %w", prURL, err)
	}
	emit("pull_request", "complete", prURL)
	return nil
}

func catalogPullRequestTitle(row results.Result, generated string) string {
	title := strings.Join(strings.Fields(generated), " ")
	if title != "" {
		return title
	}
	title = "Update " + row.Package + " adversary rules"
	if rule := strings.TrimRight(strings.Join(strings.Fields(row.ProposedRule), " "), "."); rule != "" {
		title = "Update " + row.Package + ": " + rule
	}
	runes := []rune(title)
	if len(runes) > 120 {
		title = strings.TrimSpace(string(runes[:119])) + "…"
	}
	return title
}

func configForWorktree(cfg workspace.Config, sourceWorkspace, targetWorkspace string) (workspace.Config, error) {
	root := strings.TrimSpace(cfg.Adversaries.Root)
	if !filepath.IsAbs(root) {
		return cfg, nil
	}
	canonicalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return workspace.Config{}, fmt.Errorf("resolve configured adversary root: %w", err)
	}
	relative, err := filepath.Rel(sourceWorkspace, canonicalRoot)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return workspace.Config{}, fmt.Errorf("absolute adversaries.root must be inside the catalog workspace to create a pull request")
	}
	cfg.Adversaries.Root = filepath.Join(targetWorkspace, relative)
	return cfg, nil
}

func applyCandidate(workspaceRoot string, cfg workspace.Config, row results.Result) (string, error) {
	if err := validateCandidate(row); err != nil {
		return "", err
	}
	owner := strings.TrimSpace(row.Package)
	rule := strings.TrimSpace(row.ProposedRule)

	root, err := adversaryRoot(workspaceRoot, cfg)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(root, owner)
	if rel, err := filepath.Rel(root, dir); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("adversary path escapes configured root")
	}
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if strings.TrimSpace(row.AdversaryMission) == "" {
			return "", fmt.Errorf("new adversary %q needs a mission before it can be created", owner)
		}
		if err := createAdversary(dir, owner, row.AdversaryMission); err != nil {
			return "", err
		}
	} else if err != nil {
		return "", err
	}
	if strings.TrimSpace(row.AdversaryMission) != "" {
		if err := addManifestEntry(filepath.Join(workspaceRoot, "adversarylabs.yaml"), owner, strings.TrimSpace(row.AdversaryMission)); err != nil {
			return "", err
		}
	}

	target := policyFile(dir)
	marker := "<!-- adversary-catalog-train:" + row.ID + " -->"
	if err := appendRule(target, marker, rule, evidenceURL(row)); err != nil {
		return "", err
	}
	return target, nil
}

func validateCandidate(row results.Result) error {
	if row.Status == results.StatusDismissed {
		return fmt.Errorf("candidate %s is dismissed", row.ID)
	}
	if row.Status == results.StatusCovered {
		return fmt.Errorf("candidate %s is already covered", row.ID)
	}
	owner := strings.TrimSpace(row.Package)
	if owner == "" || owner == "unassigned" {
		return fmt.Errorf("choose an adversary before applying this candidate")
	}
	if !safeID.MatchString(owner) {
		return fmt.Errorf("invalid adversary id %q", owner)
	}
	if strings.TrimSpace(row.ProposedRule) == "" {
		return fmt.Errorf("add a proposed rule before applying this candidate")
	}
	return nil
}

func requireCommand(ctx context.Context, run commandRunner, dir, name string, args ...string) ([]byte, error) {
	out, err := run(ctx, dir, name, args...)
	if err != nil {
		message := commandFailureMessage(string(out))
		if message != "" {
			return nil, fmt.Errorf("%s: %w", message, err)
		}
		return nil, err
	}
	return out, nil
}

func commandFailureMessage(output string) string {
	message := strings.TrimSpace(output)
	if failures := failingTAPBlocks(message); failures != "" {
		message = failures
	}
	const maxRunes = 6000
	runes := []rune(message)
	if len(runes) > maxRunes {
		const tailRunes = 1200
		message = string(runes[:maxRunes-tailRunes]) + "\n…\n" + string(runes[len(runes)-tailRunes:])
	}
	return message
}

// failingTAPBlocks keeps every failed subtest and its diagnostic block. A test
// runner normally prints failures in execution order followed by a potentially
// very long list of passing tests. Keeping only the tail can therefore hide the
// exact failures from both the UI and the model that repairs generated rules.
func failingTAPBlocks(output string) string {
	lines := strings.Split(output, "\n")
	blocks := make([]string, 0)
	lastStart := -1
	for index, line := range lines {
		if !strings.HasPrefix(strings.TrimSpace(line), "not ok ") {
			continue
		}
		start := index
		for candidate := index - 1; candidate >= 0; candidate-- {
			trimmed := strings.TrimSpace(lines[candidate])
			if strings.HasPrefix(trimmed, "# Subtest:") {
				start = candidate
				break
			}
			if strings.HasPrefix(trimmed, "ok ") || strings.HasPrefix(trimmed, "not ok ") {
				break
			}
		}
		if start == lastStart {
			continue
		}
		end := len(lines)
		for candidate := index + 1; candidate < len(lines); candidate++ {
			trimmed := strings.TrimSpace(lines[candidate])
			if strings.HasPrefix(trimmed, "# Subtest:") || strings.HasPrefix(trimmed, "ok ") || strings.HasPrefix(trimmed, "not ok ") {
				end = candidate
				break
			}
			if strings.HasPrefix(trimmed, "1..") || strings.HasPrefix(trimmed, "# tests ") {
				end = candidate
				break
			}
		}
		blocks = append(blocks, strings.TrimSpace(strings.Join(lines[start:end], "\n")))
		lastStart = start
	}
	return strings.Join(blocks, "\n\n")
}

func remoteDefaultBranch(ctx context.Context, run commandRunner, root string) (string, string, error) {
	if out, err := run(ctx, root, "git", "symbolic-ref", "--short", "refs/remotes/origin/HEAD"); err == nil {
		ref := strings.TrimSpace(string(out))
		if strings.HasPrefix(ref, "origin/") && len(ref) > len("origin/") {
			return ref, strings.TrimPrefix(ref, "origin/"), nil
		}
	}
	for _, branch := range []string{"main", "master"} {
		ref := "refs/remotes/origin/" + branch
		if _, err := run(ctx, root, "git", "show-ref", "--verify", "--quiet", ref); err == nil {
			return "origin/" + branch, branch, nil
		}
	}
	return "", "", fmt.Errorf("cannot determine the remote default branch; configure origin/HEAD")
}

func pullRequestBranch(row results.Result) string {
	owner := strings.Trim(strings.ToLower(row.Package), "-._")
	id := regexp.MustCompile(`[^a-zA-Z0-9._-]+`).ReplaceAllString(row.ID, "-")
	if len(owner) > 32 {
		owner = owner[:32]
	}
	if len(id) > 24 {
		id = id[:24]
	}
	return fmt.Sprintf("adversary/train-%s-%s-%d", owner, id, time.Now().UTC().UnixMilli())
}

func pullRequestBody(row results.Result, generatedTarget, generatedSummary string, validated, runtimeSynchronized bool) string {
	var body strings.Builder
	fmt.Fprintf(&body, "## Catalog training proposal\n\n- Adversary: `%s`\n- Candidate: `%s`\n", row.Package, row.ID)
	if evidence := evidenceURL(row); evidence != "" {
		fmt.Fprintf(&body, "- Evidence: %s\n", evidence)
	}
	if runtimeSynchronized {
		fmt.Fprintln(&body, "- Managed runtime template: synchronized")
	}
	rule := managedRule{}
	if filepath.Base(generatedTarget) == "rule.yaml" {
		if raw, err := os.ReadFile(generatedTarget); err == nil {
			_ = yaml.Unmarshal(raw, &rule)
		}
	}
	if rule.ID != "" && rule.Summary != "" && rule.Guidance != "" {
		fmt.Fprintf(&body, "\n## Generated rule\n\n**%s** (`%s`)\n\n%s\n\n- Default severity: `%s`\n- Minimum confidence: `%s`\n", strings.TrimSpace(rule.Summary), rule.ID, strings.TrimSpace(rule.Guidance), rule.Severity, rule.Confidence)
	} else {
		summary := strings.TrimSpace(generatedSummary)
		if summary == "" {
			summary = strings.TrimSpace(row.ProposedRule)
		}
		fmt.Fprintf(&body, "\n## Generated change\n\n%s\n", summary)
	}
	if validated {
		if rule.ID != "" {
			fmt.Fprintln(&body, "\n## Validation\n\n- Generated finding and no-finding cases passed semantic evaluation.\n- The isolated adversary package built, tested, validated, and packed successfully.")
		} else {
			fmt.Fprintln(&body, "\n## Validation\n\n- Deterministic finding and close non-finding cases passed through the production runtime.\n- The isolated adversary package built, tested, validated, and packed successfully.")
		}
	}
	fmt.Fprintln(&body, "\nGenerated locally by `adversary catalog train inspect`; review and edit before merging.")
	return body.String()
}

func lastURL(output string) string {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		candidate := strings.TrimSpace(lines[i])
		if strings.HasPrefix(candidate, "https://") || strings.HasPrefix(candidate, "http://") {
			return candidate
		}
	}
	return ""
}

func adversaryRoot(workspaceRoot string, cfg workspace.Config) (string, error) {
	root := strings.TrimSpace(cfg.Adversaries.Root)
	if root == "" {
		return "", fmt.Errorf("apply-to-catalog requires adversaries.root")
	}
	if !filepath.IsAbs(root) {
		root = filepath.Join(workspaceRoot, root)
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	return abs, nil
}

func policyFile(dir string) string {
	for _, rel := range []string{filepath.Join("agent", "scope.md"), filepath.Join("docs", "scope.md"), "README.md"} {
		path := filepath.Join(dir, rel)
		if st, err := os.Stat(path); err == nil && !st.IsDir() {
			return path
		}
	}
	return filepath.Join(dir, "README.md")
}

func appendRule(path, marker, rule, evidence string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read adversary policy: %w", err)
	}
	if strings.Contains(string(raw), marker) {
		return nil
	}
	body := strings.TrimRight(string(raw), "\n")
	if !strings.Contains(body, "## Learned rules") {
		body += "\n\n## Learned rules\n"
	}
	body += "\n- " + strings.ReplaceAll(rule, "\n", " ")
	if evidence != "" {
		body += " ([evidence](" + evidence + "))"
	}
	body += "\n  " + marker + "\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		return fmt.Errorf("write adversary policy: %w", err)
	}
	return nil
}

func evidenceURL(row results.Result) string {
	if strings.TrimSpace(row.CommentURL) != "" {
		return strings.TrimSpace(row.CommentURL)
	}
	return strings.TrimSpace(row.PRURL)
}

func createAdversary(dir, id, mission string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create adversary: %w", err)
	}
	title := strings.ReplaceAll(id, "-", " ")
	readme := fmt.Sprintf("# %s\n\n## Purpose\n\n%s\n", title, strings.TrimSpace(mission))
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte(readme), 0o644); err != nil {
		return fmt.Errorf("create adversary policy: %w", err)
	}
	return nil
}

func addManifestEntry(path, id, summary string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read catalog manifest: %w", err)
	}
	var document yaml.Node
	if err := yaml.Unmarshal(raw, &document); err != nil {
		return fmt.Errorf("parse catalog manifest: %w", err)
	}
	adversaries := mappingPath(&document, "spec", "adversaries")
	if adversaries == nil || adversaries.Kind != yaml.SequenceNode {
		return fmt.Errorf("catalog manifest has no spec.adversaries list")
	}
	for _, item := range adversaries.Content {
		if valueAt(item, "id") == id {
			return nil
		}
	}
	entry := &yaml.Node{Kind: yaml.MappingNode}
	for _, pair := range [][2]string{{"id", id}, {"path", "adversaries/" + id}, {"summary", summary}} {
		entry.Content = append(entry.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: pair[0]}, &yaml.Node{Kind: yaml.ScalarNode, Value: pair[1]})
	}
	adversaries.Content = append(adversaries.Content, entry)
	out, err := yaml.Marshal(&document)
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o644)
}

func mappingPath(root *yaml.Node, keys ...string) *yaml.Node {
	node := root
	if node.Kind == yaml.DocumentNode && len(node.Content) == 1 {
		node = node.Content[0]
	}
	for _, key := range keys {
		if node.Kind != yaml.MappingNode {
			return nil
		}
		var next *yaml.Node
		for i := 0; i+1 < len(node.Content); i += 2 {
			if node.Content[i].Value == key {
				next = node.Content[i+1]
				break
			}
		}
		if next == nil {
			return nil
		}
		node = next
	}
	return node
}

func valueAt(node *yaml.Node, key string) string {
	if node == nil || node.Kind != yaml.MappingNode {
		return ""
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1].Value
		}
	}
	return ""
}
