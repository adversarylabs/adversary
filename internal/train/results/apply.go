package results

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/adversarylabs/adversary/internal/githubapi"
)

// ApplyOptions controls writing a result into a local package repo.
type ApplyOptions struct {
	// PackagePath is the absolute path to the local adversary package.
	PackagePath string
	// CreateBranch when true runs git checkout -b and commit (if .git present).
	CreateBranch bool
	// Branch name override (default train/<package>/<id>).
	Branch string
	// CreateIssue opens a GitHub issue on the package repo (default true from CLI).
	CreateIssue bool
	// IssueClient is optional; when nil and CreateIssue, a token client is built from env.
	IssueClient IssueCreator
	// Context for GitHub API (defaults to Background).
	Context context.Context
}

// IssueCreator creates a GitHub issue (usually *githubapi.Client).
type IssueCreator interface {
	CreateIssue(ctx context.Context, owner, repo string, in githubapi.CreateIssueInput) (githubapi.Issue, error)
}

// ApplyResult is what apply wrote.
type ApplyResult struct {
	ID          string
	Path        string
	Branch      string
	IssueURL    string
	Committed   bool
	AlreadyDone bool
}

// Apply writes the draft into the package and marks the result applied.
// Default: docs/train-drafts/<id>.md under the package. Optional git branch+commit
// and GitHub issue on the package remote for coding agents to pick up.
func Apply(stateRoot, id string, opts ApplyOptions) (ApplyResult, error) {
	r, err := Get(stateRoot, id)
	if err != nil {
		return ApplyResult{}, err
	}
	if r.Status == StatusApplied {
		return ApplyResult{
			ID: r.ID, Path: r.AppliedPath, Branch: r.Branch,
			IssueURL: r.IssueURL, AlreadyDone: true,
		}, nil
	}
	if opts.PackagePath == "" {
		return ApplyResult{}, fmt.Errorf("package path required for apply")
	}
	abs, err := filepath.Abs(opts.PackagePath)
	if err != nil {
		return ApplyResult{}, err
	}
	st, err := os.Stat(abs)
	if err != nil || !st.IsDir() {
		return ApplyResult{}, fmt.Errorf("package path not a directory: %s", abs)
	}

	draftDir := filepath.Join(abs, "docs", "train-drafts")
	if err := os.MkdirAll(draftDir, 0o755); err != nil {
		return ApplyResult{}, err
	}
	outPath := filepath.Join(draftDir, r.ID+".md")
	body := formatApplyMarkdown(r)
	if err := os.WriteFile(outPath, []byte(body), 0o644); err != nil {
		return ApplyResult{}, err
	}

	ar := ApplyResult{ID: r.ID, Path: outPath}
	branch := opts.Branch
	if branch == "" {
		pkg := r.Package
		if pkg == "" {
			pkg = "package"
		}
		branch = fmt.Sprintf("train/%s/%s", sanitizeBranch(pkg), r.ID)
	}

	if opts.CreateBranch {
		if committed, b, err := gitCommitDraft(abs, branch, outPath, r); err == nil {
			ar.Committed = committed
			ar.Branch = b
		}
		// git failures are non-fatal: draft file still applied
	}

	var issueErr error
	if opts.CreateIssue {
		issueURL, err := createApplyIssue(opts, abs, r, outPath)
		if err != nil {
			issueErr = err
		} else {
			ar.IssueURL = issueURL
		}
	}

	// Always persist applied after the draft is on disk — even if the GitHub
	// issue step fails — so results ls reflects the user's action.
	r.Status = StatusApplied
	r.AppliedAt = time.Now().UTC()
	r.AppliedPath = outPath
	r.Branch = ar.Branch
	if ar.IssueURL != "" {
		r.IssueURL = ar.IssueURL
	}
	if err := SaveResult(stateRoot, r); err != nil {
		if issueErr != nil {
			return ar, fmt.Errorf("save applied status: %w (also create issue: %v)", err, issueErr)
		}
		return ar, err
	}
	if issueErr != nil {
		return ar, fmt.Errorf("create GitHub issue: %w\n  (marked applied; draft at %s; re-run apply or open issue manually)", issueErr, outPath)
	}
	return ar, nil
}

func createApplyIssue(opts ApplyOptions, packagePath string, r Result, draftPath string) (string, error) {
	ctx := opts.Context
	if ctx == nil {
		ctx = context.Background()
	}
	client := opts.IssueClient
	if client == nil {
		tok, err := githubapi.RequireToken()
		if err != nil {
			return "", err
		}
		client = githubapi.NewClient(tok)
	}
	ref, err := githubapi.ResolvePackageGitHubRepo(packagePath)
	if err != nil {
		return "", err
	}
	issue, err := client.CreateIssue(ctx, ref.Owner, ref.Name, githubapi.CreateIssueInput{
		Title:  issueTitle(r),
		Body:   formatIssueBody(r, draftPath),
		Labels: issueLabels(r),
	})
	if err != nil {
		return "", err
	}
	return issue.HTMLURL, nil
}

func issueTitle(r Result) string {
	pkg := r.Package
	if pkg == "" {
		pkg = "adversary"
	}
	kind := KindLabel(r.Kind)
	base := strings.TrimSpace(r.Title)
	if base == "" {
		base = strings.TrimSpace(r.Summary)
	}
	base = soft(base, 72)
	if base == "" {
		return fmt.Sprintf("train: %s for %s (%s)", kind, pkg, r.ID)
	}
	return fmt.Sprintf("train/%s: %s — %s", pkg, kind, base)
}

func issueLabels(r Result) []string {
	labels := []string{"train", "adversary-train"}
	if r.Package != "" {
		labels = append(labels, "adversary:"+sanitizeBranch(r.Package))
	}
	switch normalizeKind(r.Kind) {
	case KindMiss:
		labels = append(labels, "train-miss")
	case KindFalsePositive:
		labels = append(labels, "train-false-positive")
	case KindDraft:
		labels = append(labels, "train-draft")
	case KindHuman:
		labels = append(labels, "train-human")
	}
	return labels
}

// formatIssueBody is agent-oriented: spirit, when to post, variance — not a fixed quote to emit.
func formatIssueBody(r Result, draftPath string) string {
	spirit := ClassifyCommentSpirit(r.Summary)
	var b strings.Builder
	fmt.Fprintf(&b, "## Task for coding agent\n\n")
	fmt.Fprintf(&b, "Implement this **adversary train** result in the **`%s`** package.\n\n", r.Package)
	switch normalizeKind(r.Kind) {
	case KindMiss:
		fmt.Fprintf(&b, "The human review signal was a **`%s`**. The package should learn to emit the same *class* of ", spirit)
		fmt.Fprintf(&b, "feedback in persona voice — **not** the exact human sentence, and not a fake bug if this was a ship/OK signal.\n\n")
	case KindFalsePositive:
		fmt.Fprintf(&b, "The package over-fired relative to human review. Quiet or gate this class of finding.\n\n")
	default:
		fmt.Fprintf(&b, "Improve the package as described below.\n\n")
	}

	fmt.Fprintf(&b, "### One-line goal\n\n%s\n\n", strings.TrimSpace(r.Title))
	if r.Title != r.Summary && strings.TrimSpace(r.Summary) != "" {
		fmt.Fprintf(&b, "Human example (do **not** hard-code): _%s_\n\n", soft(collapseWS(r.Summary), 200))
	}
	fmt.Fprintf(&b, "### Kind\n\n`%s` — %s\n\n", KindLabel(r.Kind), KindExplain(r.Kind, r.Status))
	fmt.Fprintf(&b, "### Source\n\n")
	fmt.Fprintf(&b, "- Result ID: `%s`\n", r.ID)
	fmt.Fprintf(&b, "- Package: `%s`\n", r.Package)
	fmt.Fprintf(&b, "- Run: `%s`\n", r.RunID)
	if r.CaseID != "" {
		fmt.Fprintf(&b, "- Case: `%s`\n", r.CaseID)
	}
	if r.ConcernID != "" {
		fmt.Fprintf(&b, "- Concern: `%s`\n", r.ConcernID)
	}
	if r.PRURL != "" {
		fmt.Fprintf(&b, "- Human PR: %s\n", r.PRURL)
	}
	if r.PRTitle != "" {
		fmt.Fprintf(&b, "- PR title: %s\n", r.PRTitle)
	}

	// Prefer structured draft; rebuild if legacy thin body.
	draft := strings.TrimSpace(r.DraftBody)
	if draft == "" || !strings.Contains(draft, "### When to post") {
		draft = strings.TrimSpace(BuildMissDraft(MissDraftInput{
			Package:  r.Package,
			Summary:  r.Summary,
			PRURL:    r.PRURL,
			PRTitle:  r.PRTitle,
			CaseID:   r.CaseID,
			VoicePkg: isVoicePackage(r.Package),
		}))
	}
	fmt.Fprintf(&b, "\n### Train brief (spirit + when + variance)\n\n")
	b.WriteString(draft)
	b.WriteString("\n\n")

	fmt.Fprintf(&b, "### Implementation requirements\n\n")
	fmt.Fprintf(&b, "1. **Do not** paste the human quote as a constant finding string.\n")
	fmt.Fprintf(&b, "2. Teach **when** this class fires (see brief); ship-signals are opinion/positive, not invented defects.\n")
	fmt.Fprintf(&b, "3. Use **`agent/voice.md`** (LLM rewrite at emit time) so wording varies while spirit stays stable.\n")
	fmt.Fprintf(&b, "4. Add tests for the **class**, not one PR-specific sentence.\n\n")

	fmt.Fprintf(&b, "### Likely files\n\n")
	fmt.Fprintf(&b, "- `src/` — rules / opinion / when-to-ship heuristics\n")
	fmt.Fprintf(&b, "- `agent/voice.md` — persona tone for rewrite\n")
	fmt.Fprintf(&b, "- `agent/scope.md` — only if mission should expand\n")
	fmt.Fprintf(&b, "- `test/` / fixtures — class coverage\n\n")
	fmt.Fprintf(&b, "### Acceptance\n\n")
	fmt.Fprintf(&b, "- [ ] Package builds and tests pass\n")
	fmt.Fprintf(&b, "- [ ] On similar landable changes, persona can emit a ship/OK-class signal (if spirit is ship)\n")
	fmt.Fprintf(&b, "- [ ] Surface form varies (voice/LLM); not a single fixed string\n")
	fmt.Fprintf(&b, "- [ ] No false defects invented solely to “match” praise\n")
	fmt.Fprintf(&b, "- [ ] Focused change; no unrelated rewrites\n\n")
	if draftPath != "" {
		fmt.Fprintf(&b, "### Local draft copy\n\n`%s`\n\n", draftPath)
	}
	fmt.Fprintf(&b, "---\n_Opened by `adversary train results apply`._\n")
	return b.String()
}

// Dismiss marks a result dismissed (not applied).
func Dismiss(stateRoot, id string) error {
	r, err := Get(stateRoot, id)
	if err != nil {
		return err
	}
	r.Status = StatusDismissed
	return SaveResult(stateRoot, r)
}

func formatApplyMarkdown(r Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Train draft %s\n\n", r.ID)
	fmt.Fprintf(&b, "- **Package:** `%s`\n", r.Package)
	fmt.Fprintf(&b, "- **Kind:** %s — %s\n", KindLabel(r.Kind), KindExplain(r.Kind, r.Status))
	fmt.Fprintf(&b, "- **Title:** %s\n", r.Title)
	fmt.Fprintf(&b, "- **Human example:** %s\n", r.Summary)
	if r.PRURL != "" {
		fmt.Fprintf(&b, "- **PR:** %s\n", r.PRURL)
	}
	fmt.Fprintf(&b, "- **Run:** `%s`\n", r.RunID)
	fmt.Fprintf(&b, "\n_Applied by `adversary train results apply`. Implement spirit + when-to-post; do not hard-code the human sentence._\n\n")
	draft := strings.TrimSpace(r.DraftBody)
	if draft == "" || !strings.Contains(draft, "### When to post") {
		draft = strings.TrimSpace(BuildMissDraft(MissDraftInput{
			Package:  r.Package,
			Summary:  r.Summary,
			PRURL:    r.PRURL,
			PRTitle:  r.PRTitle,
			CaseID:   r.CaseID,
			VoicePkg: isVoicePackage(r.Package),
		}))
	}
	b.WriteString(draft)
	if !strings.HasSuffix(draft, "\n") {
		b.WriteByte('\n')
	}
	return b.String()
}

func sanitizeBranch(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '/' {
			b.WriteRune(r)
		} else if r == ' ' || r == ':' {
			b.WriteByte('-')
		}
	}
	out := b.String()
	if out == "" {
		return "pkg"
	}
	return out
}

func gitCommitDraft(repo, branch, filePath string, r Result) (bool, string, error) {
	if _, err := os.Stat(filepath.Join(repo, ".git")); err != nil {
		return false, "", err
	}
	if _, err := exec.LookPath("git"); err != nil {
		return false, "", err
	}
	// Create / switch branch
	_ = exec.Command("git", "-C", repo, "checkout", "-B", branch).Run()
	rel, err := filepath.Rel(repo, filePath)
	if err != nil {
		rel = filePath
	}
	if err := exec.Command("git", "-C", repo, "add", "--", rel).Run(); err != nil {
		return false, branch, err
	}
	msg := fmt.Sprintf("train: apply draft %s — %s", r.ID, soft(r.Summary, 60))
	cmd := exec.Command("git", "-C", repo, "commit", "-m", msg)
	if out, err := cmd.CombinedOutput(); err != nil {
		// nothing to commit is ok
		if strings.Contains(string(out), "nothing to commit") {
			return false, branch, nil
		}
		return false, branch, fmt.Errorf("git commit: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return true, branch, nil
}
