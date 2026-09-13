package catalogapply

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	pathpkg "path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/adversarylabs/adversary/internal/cataloginit"
	"github.com/adversarylabs/adversary/internal/train/results"
	"github.com/adversarylabs/adversary/internal/train/workspace"
	"gopkg.in/yaml.v3"
)

const (
	maxSourceFiles = 40
	maxSourceBytes = 240 << 10
	maxPlanFiles   = 16
	maxPlanBytes   = 512 << 10
)

// ChangePlanner turns reviewed evidence plus the current adversary source into
// a bounded, reviewable catalog patch. The returned paths are workspace-relative.
type ChangePlanner func(context.Context, ChangeRequest) (ChangePlan, error)

type ChangeRequest struct {
	CandidateID        string       `json:"candidate_id"`
	Adversary          string       `json:"adversary"`
	AdversaryMission   string       `json:"adversary_mission,omitempty"`
	ProposedRule       string       `json:"proposed_rule"`
	Evidence           string       `json:"evidence"`
	EvidenceComment    string       `json:"evidence_comment"`
	EvidenceFile       string       `json:"evidence_file,omitempty"`
	EvidenceDiff       string       `json:"evidence_diff,omitempty"`
	ExistingAdversary  bool         `json:"existing_adversary"`
	Executable         bool         `json:"executable"`
	PolicyDriven       bool         `json:"policy_driven"`
	Files              []SourceFile `json:"files"`
	ValidationFeedback string       `json:"validation_feedback,omitempty"`
	PreviousPlanFiles  []string     `json:"previous_plan_files,omitempty"`
}

type SourceFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

type ChangePlan struct {
	Summary string       `json:"summary"`
	Files   []ChangeFile `json:"files"`
}

type ChangeFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// ApplyPlanned updates the current checkout with a substantive model-planned
// adversary change. It does not commit the result.
func ApplyPlanned(ctx context.Context, stateRoot, workspaceRoot string, cfg workspace.Config, id string, planner ChangePlanner) error {
	row, err := results.Get(stateRoot, id)
	if err != nil {
		return err
	}
	target, err := applyPlannedCandidate(ctx, workspaceRoot, cfg, row, planner)
	if err != nil {
		return err
	}
	root, err := adversaryRoot(workspaceRoot, cfg)
	if err != nil {
		return err
	}
	if err := validateRunnablePackage(ctx, filepath.Join(root, row.Package), execCommand); err != nil {
		return err
	}
	row.Status = results.StatusApplied
	row.AppliedAt = nowUTC()
	row.AppliedPath = target
	return results.SaveResult(stateRoot, row)
}

func applyPlannedCandidate(ctx context.Context, workspaceRoot string, cfg workspace.Config, row results.Result, planner ChangePlanner) (string, error) {
	if planner == nil {
		return "", fmt.Errorf("catalog change generation needs a configured model provider")
	}
	if err := validateCandidate(row); err != nil {
		return "", err
	}
	root, err := adversaryRoot(workspaceRoot, cfg)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(root, row.Package)
	_, policyErr := os.Stat(filepath.Join(dir, "README.md"))
	wasExisting := policyErr == nil
	if os.IsNotExist(policyErr) {
		if err := createAdversary(dir, row.Package, row.AdversaryMission); err != nil {
			return "", err
		}
	} else if policyErr != nil {
		return "", policyErr
	}
	if _, err := cataloginit.EnsureRunnableAdversary(dir, row.Package); err != nil {
		return "", fmt.Errorf("make catalog adversary runnable: %w", err)
	}
	request, root, dir, err := buildChangeRequest(workspaceRoot, cfg, row)
	if err != nil {
		return "", err
	}
	request.ExistingAdversary = wasExisting
	var target string
	for attempt := 0; attempt < 2; attempt++ {
		plan, err := planner(ctx, request)
		if err != nil {
			return "", fmt.Errorf("generate substantive adversary change: %w", err)
		}
		target, err = writeChangePlan(workspaceRoot, root, dir, row, request, plan)
		if err == nil {
			break
		}
		if attempt == 1 || !isRetryablePlanError(err) {
			return "", err
		}
		request.ValidationFeedback = err.Error() + ". Regenerate the complete change and correct this problem."
		request.PreviousPlanFiles = request.PreviousPlanFiles[:0]
		for _, file := range plan.Files {
			request.PreviousPlanFiles = append(request.PreviousPlanFiles, file.Path)
		}
	}
	if !request.ExistingAdversary {
		if err := addManifestEntry(filepath.Join(workspaceRoot, "adversarylabs.yaml"), row.Package, row.AdversaryMission); err != nil {
			return "", err
		}
	}
	return target, nil
}

func isRetryablePlanError(err error) bool {
	message := err.Error()
	return strings.HasPrefix(message, "generated change") || strings.HasPrefix(message, "validate generated regression")
}

func buildChangeRequest(workspaceRoot string, cfg workspace.Config, row results.Result) (ChangeRequest, string, string, error) {
	root, err := adversaryRoot(workspaceRoot, cfg)
	if err != nil {
		return ChangeRequest{}, "", "", err
	}
	dir := filepath.Join(root, row.Package)
	rel, err := filepath.Rel(root, dir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return ChangeRequest{}, "", "", fmt.Errorf("adversary path escapes configured root")
	}
	_, statErr := os.Stat(dir)
	exists := statErr == nil
	if statErr != nil && !os.IsNotExist(statErr) {
		return ChangeRequest{}, "", "", statErr
	}
	if !exists && strings.TrimSpace(row.AdversaryMission) == "" {
		return ChangeRequest{}, "", "", fmt.Errorf("new adversary %q needs a mission before it can be created", row.Package)
	}
	files, executable, policyDriven, err := readAdversaryFiles(workspaceRoot, dir)
	if err != nil {
		return ChangeRequest{}, "", "", err
	}
	return ChangeRequest{
		CandidateID: row.ID, Adversary: row.Package, AdversaryMission: row.AdversaryMission,
		ProposedRule: row.ProposedRule, Evidence: evidenceURL(row), EvidenceComment: row.Summary,
		EvidenceFile: row.File, EvidenceDiff: row.DiffHunk, ExistingAdversary: exists,
		Executable: executable, PolicyDriven: policyDriven, Files: files,
	}, root, dir, nil
}

func readAdversaryFiles(workspaceRoot, dir string) ([]SourceFile, bool, bool, error) {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil, false, false, nil
	}
	var files []SourceFile
	total := 0
	executable := false
	policyDriven := false
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if path != dir && (entry.Name() == "node_modules" || entry.Name() == "dist" || entry.Name() == ".git") {
				return filepath.SkipDir
			}
			return nil
		}
		if len(files) >= maxSourceFiles || total >= maxSourceBytes {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 || strings.HasSuffix(entry.Name(), ".lock") || entry.Name() == "package-lock.json" {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if len(raw) > 64<<10 || total+len(raw) > maxSourceBytes {
			return nil
		}
		rel, err := filepath.Rel(workspaceRoot, path)
		if err != nil {
			return err
		}
		name := entry.Name()
		if name == "package.json" || name == "go.mod" || name == "pyproject.toml" {
			executable = true
		}
		if name == "package.json" && strings.Contains(string(raw), `"adversarylabsCatalogRuntime"`) {
			policyDriven = true
		}
		files = append(files, SourceFile{Path: filepath.ToSlash(rel), Content: string(raw)})
		total += len(raw)
		return nil
	})
	if err != nil {
		return nil, false, false, fmt.Errorf("read adversary source: %w", err)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, executable, policyDriven, nil
}

type regressionSpec struct {
	Version     int    `yaml:"version"`
	CandidateID string `yaml:"candidate_id"`
	Adversary   string `yaml:"adversary"`
	Evidence    string `yaml:"evidence"`
	Rule        string `yaml:"rule"`
	Cases       []struct {
		Name     string `yaml:"name"`
		Input    string `yaml:"review_input"`
		Expected string `yaml:"expected"`
		Reason   string `yaml:"reason"`
	} `yaml:"cases"`
}

func writeChangePlan(workspaceRoot, root, dir string, row results.Result, request ChangeRequest, plan ChangePlan) (string, error) {
	if len(plan.Files) < 2 || len(plan.Files) > maxPlanFiles {
		return "", fmt.Errorf("generated change must contain an operative adversary edit and regression coverage (got %d files)", len(plan.Files))
	}
	adversaryRel, err := filepath.Rel(workspaceRoot, dir)
	if err != nil {
		return "", err
	}
	adversaryPrefix := filepath.ToSlash(adversaryRel) + "/"
	existing := make(map[string]string, len(request.Files))
	for _, file := range request.Files {
		existing[file.Path] = file.Content
	}
	total, operative, regression := 0, "", ""
	implementation, nativeRegression := false, false
	newImplementation, runtimeRegression := false, false
	var newSourcePaths []string
	finalSources := make(map[string]string)
	for path, content := range existing {
		if strings.Contains(path, "/src/") {
			finalSources[path] = content
		}
	}
	seen := map[string]bool{}
	for index := range plan.Files {
		file := &plan.Files[index]
		clean := filepath.ToSlash(filepath.Clean(file.Path))
		if clean == "." || filepath.IsAbs(file.Path) || clean == ".." || strings.HasPrefix(clean, "../") || seen[clean] {
			return "", fmt.Errorf("generated change contains unsafe or duplicate path %q", file.Path)
		}
		seen[clean] = true
		if !strings.HasPrefix(clean, adversaryPrefix) {
			return "", fmt.Errorf("generated change may only edit %s", adversaryPrefix)
		}
		if strings.Contains(clean, "/node_modules/") || strings.Contains(clean, "/.git/") || strings.Contains(clean, "/dist/") {
			return "", fmt.Errorf("generated change contains forbidden path %q", clean)
		}
		total += len(file.Content)
		if total > maxPlanBytes {
			return "", fmt.Errorf("generated change exceeds %d bytes", maxPlanBytes)
		}
		relInAdversary := strings.TrimPrefix(clean, adversaryPrefix)
		if request.PolicyDriven && (strings.HasPrefix(relInAdversary, "dist/") || relInAdversary == "adversary.yaml" || relInAdversary == "package.json" || relInAdversary == "package-lock.json") {
			return "", fmt.Errorf("policy-driven catalog training may not rewrite generated output or package metadata (%s)", clean)
		}
		base := filepath.Base(clean)
		changed := existing[clean] != file.Content
		operativePolicy := base == "README.md" || relInAdversary == "agent/scope.md" || relInAdversary == "docs/scope.md"
		if request.PolicyDriven {
			operativePolicy = relInAdversary == "README.md"
		}
		if changed && operativePolicy {
			operative = clean
		}
		if changed && strings.HasPrefix(relInAdversary, "src/") {
			implementation = true
			if _, existed := existing[clean]; !existed {
				newImplementation = true
				newSourcePaths = append(newSourcePaths, clean)
			}
		}
		if strings.HasPrefix(relInAdversary, "src/") {
			finalSources[clean] = file.Content
		}
		if changed && strings.HasPrefix(relInAdversary, "tests/") && (strings.HasSuffix(clean, ".yaml") || strings.HasSuffix(clean, ".yml")) {
			canonical, err := canonicalRegression([]byte(file.Content), row)
			if err != nil {
				return "", fmt.Errorf("validate generated regression %s: %w", clean, err)
			}
			total += len(canonical) - len(file.Content)
			if total > maxPlanBytes {
				return "", fmt.Errorf("generated change exceeds %d bytes", maxPlanBytes)
			}
			file.Content = string(canonical)
			regression = clean
		} else if changed && (strings.Contains(strings.ToLower(base), "test") || strings.Contains(strings.ToLower(base), "spec")) {
			regression = clean
			nativeRegression = true
			if strings.Contains(file.Content, "/src/index") {
				runtimeRegression = true
			}
		}
	}
	if operative == "" {
		if request.PolicyDriven {
			return "", fmt.Errorf("generated change did not update the policy-driven adversary's operative README.md")
		}
		return "", fmt.Errorf("generated change did not update the adversary's operative README or scope")
	}
	if regression == "" {
		return "", fmt.Errorf("generated change did not add regression coverage")
	}
	if request.Executable && !implementation {
		return "", fmt.Errorf("generated change did not update the executable adversary implementation")
	}
	if request.Executable && !nativeRegression {
		return "", fmt.Errorf("generated change did not update the executable adversary's native tests")
	}
	if request.Executable && request.PolicyDriven && !runtimeRegression {
		return "", fmt.Errorf("generated policy-driven change did not add a native test through src/index")
	}
	if request.Executable && newImplementation {
		entrypoint := adversaryPrefix + "src/index.ts"
		if _, hasTypeScriptEntrypoint := finalSources[entrypoint]; hasTypeScriptEntrypoint {
			reachable := reachableSourceFiles(finalSources, entrypoint)
			var disconnected []string
			for _, path := range newSourcePaths {
				if !reachable[path] {
					disconnected = append(disconnected, path)
				}
			}
			if len(disconnected) > 0 {
				return "", fmt.Errorf("generated change added implementation modules that are not reachable from src/index: %s", strings.Join(disconnected, ", "))
			}
		}
	}
	if request.Executable && newImplementation && !runtimeRegression {
		return "", fmt.Errorf("generated change added an implementation module but did not add a runtime integration test through src/index")
	}
	for _, file := range plan.Files {
		path := filepath.Join(workspaceRoot, filepath.FromSlash(file.Path))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return "", err
		}
		if err := os.WriteFile(path, []byte(file.Content), 0o644); err != nil {
			return "", fmt.Errorf("write generated catalog file: %w", err)
		}
	}
	_ = root // retained in the signature to make the trust boundary explicit.
	return filepath.Join(workspaceRoot, filepath.FromSlash(operative)), nil
}

var sourceImportPattern = regexp.MustCompile(`(?m)(?:from\s+|import\s*(?:\(\s*)?)["'](\.[^"']+)["']`)

func reachableSourceFiles(sources map[string]string, entrypoint string) map[string]bool {
	reachable := make(map[string]bool)
	queue := []string{entrypoint}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if reachable[current] {
			continue
		}
		content, exists := sources[current]
		if !exists {
			continue
		}
		reachable[current] = true
		for _, match := range sourceImportPattern.FindAllStringSubmatch(content, -1) {
			for _, candidate := range sourceImportCandidates(current, match[1]) {
				if _, exists := sources[candidate]; exists && !reachable[candidate] {
					queue = append(queue, candidate)
					break
				}
			}
		}
	}
	return reachable
}

func sourceImportCandidates(importer, specifier string) []string {
	base := pathpkg.Clean(pathpkg.Join(pathpkg.Dir(importer), specifier))
	candidates := []string{base}
	for _, pair := range [][2]string{{".js", ".ts"}, {".mjs", ".mts"}, {".cjs", ".cts"}} {
		if strings.HasSuffix(base, pair[0]) {
			candidates = append(candidates, strings.TrimSuffix(base, pair[0])+pair[1])
		}
	}
	if pathpkg.Ext(base) == "" {
		candidates = append(candidates, base+".ts", base+".tsx", pathpkg.Join(base, "index.ts"))
	}
	return candidates
}

func canonicalRegression(raw []byte, row results.Result) ([]byte, error) {
	var spec regressionSpec
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		repaired := quoteRegressionScalars(raw)
		if repairedErr := yaml.Unmarshal(repaired, &spec); repairedErr != nil {
			return nil, err
		}
	}
	if spec.Version != 1 || spec.CandidateID != row.ID || spec.Adversary != row.Package || spec.Evidence != evidenceURL(row) || strings.TrimSpace(spec.Rule) == "" {
		return nil, fmt.Errorf("regression must identify version 1, candidate %s, adversary %s, and its rule", row.ID, row.Package)
	}
	hasFinding, hasNoFinding := false, false
	for _, c := range spec.Cases {
		if strings.TrimSpace(c.Name) == "" || strings.TrimSpace(c.Input) == "" || strings.TrimSpace(c.Reason) == "" {
			return nil, fmt.Errorf("every regression case needs name, review_input, expected, and reason")
		}
		switch c.Expected {
		case "finding":
			hasFinding = true
		case "no_finding":
			hasNoFinding = true
		default:
			return nil, fmt.Errorf("expected must be finding or no_finding")
		}
	}
	if !hasFinding || !hasNoFinding {
		return nil, fmt.Errorf("regression needs both a finding and a no_finding case")
	}
	canonical, err := yaml.Marshal(&spec)
	if err != nil {
		return nil, err
	}
	return canonical, nil
}

// quoteRegressionScalars repairs a common model-output failure: YAML plain
// strings containing ": ". The regression schema is deliberately fixed, so
// its string fields can be made unambiguous without guessing at arbitrary YAML.
func quoteRegressionScalars(raw []byte) []byte {
	stringKeys := map[string]bool{
		"candidate_id": true, "adversary": true, "evidence": true, "rule": true,
		"name": true, "review_input": true, "expected": true, "reason": true,
	}
	lines := strings.Split(string(raw), "\n")
	for index, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "- ") {
			trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
		}
		colon := strings.Index(trimmed, ":")
		if colon < 0 || !stringKeys[strings.TrimSpace(trimmed[:colon])] {
			continue
		}
		value := strings.TrimSpace(trimmed[colon+1:])
		if value == "" || value == "|" || value == ">" || strings.HasPrefix(value, "|-") || strings.HasPrefix(value, ">-") || strings.HasPrefix(value, "\"") || strings.HasPrefix(value, "'") {
			continue
		}
		lineColon := strings.Index(line, ":")
		lines[index] = strings.TrimRight(line[:lineColon+1], " \t") + " " + strconv.Quote(value)
	}
	return []byte(strings.Join(lines, "\n"))
}

var nowUTC = func() time.Time { return time.Now().UTC() }

func validateRunnablePackage(ctx context.Context, dir string, run commandRunner) error {
	type step struct {
		name string
		args []string
		what string
	}
	var steps []step
	if _, err := os.Stat(filepath.Join(dir, "package.json")); err == nil {
		npm := "npm"
		if _, err := run(ctx, dir, npm, "--version"); err != nil {
			resolved, resolveErr := resolveNPM(ctx)
			if resolveErr != nil {
				return fmt.Errorf("locate npm for generated adversary validation: %w", resolveErr)
			}
			npm = resolved
		}
		steps = append(steps,
			step{name: npm, args: []string{"ci", "--ignore-scripts"}, what: "install locked adversary dependencies"},
			step{name: npm, args: []string{"test"}, what: "build and test generated adversary"},
		)
	} else if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
		steps = append(steps, step{name: "go", args: []string{"test", "./..."}, what: "build and test generated adversary"})
	} else {
		return fmt.Errorf("generated adversary has no supported runnable package (package.json or go.mod)")
	}
	cli, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate adversary CLI for validation: %w", err)
	}
	steps = append(steps,
		step{name: cli, args: []string{"validate", "."}, what: "validate generated adversary"},
		step{name: cli, args: []string{"pack", ".", "--check"}, what: "check generated adversary package"},
	)
	for _, current := range steps {
		if _, err := requireCommand(ctx, run, dir, current.name, current.args...); err != nil {
			return fmt.Errorf("%s: %w", current.what, err)
		}
	}
	return nil
}

func resolveNPM(ctx context.Context) (string, error) {
	names := []string{"npm"}
	if runtime.GOOS == "windows" {
		names = append(names, "npm.cmd")
	}
	for _, name := range names {
		if path, err := exec.LookPath(name); err == nil {
			return path, nil
		}
	}
	var candidates []string
	if nvmBin := strings.TrimSpace(os.Getenv("NVM_BIN")); nvmBin != "" {
		candidates = append(candidates, filepath.Join(nvmBin, names[0]))
	}
	if node, err := exec.LookPath("node"); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(node), names[0]))
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates,
			filepath.Join(home, ".volta", "bin", names[0]),
			filepath.Join(home, ".asdf", "shims", names[0]),
		)
		if matches, _ := filepath.Glob(filepath.Join(home, ".nvm", "versions", "node", "*", "bin", names[0])); len(matches) > 0 {
			sort.Sort(sort.Reverse(sort.StringSlice(matches)))
			candidates = append(candidates, matches...)
		}
	}
	for _, candidate := range candidates {
		if isExecutableFile(candidate) {
			return candidate, nil
		}
	}
	if shell := strings.TrimSpace(os.Getenv("SHELL")); filepath.IsAbs(shell) && isExecutableFile(shell) {
		command := exec.CommandContext(ctx, shell, "-lic", "command -v npm")
		if raw, err := command.Output(); err == nil {
			lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
			for index := len(lines) - 1; index >= 0; index-- {
				candidate := strings.TrimSpace(lines[index])
				if filepath.IsAbs(candidate) && isExecutableFile(candidate) {
					return candidate, nil
				}
			}
		}
	}
	return "", fmt.Errorf("npm is available in your interactive shell but not to this process; set NVM_BIN or add npm's bin directory to PATH before starting the review UI")
}

func isExecutableFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	return runtime.GOOS == "windows" || info.Mode().Perm()&0o111 != 0
}
