package catalogapply

import (
	"context"
	"encoding/json"
	"errors"
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
	"unicode/utf8"

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
	// Leave two attempts beyond the normal synthesis/quality-review cycle so a
	// semantically accepted plan can still receive compiler or test feedback and
	// be repaired without starting generation over from scratch.
	maxPlanAttempts          = 8
	maxQualityReviewAttempts = 2
	maxPolicyFiles           = 500
	maxPolicyBytes           = 1 << 20
)

// ChangePlanner turns reviewed evidence plus the current adversary source into
// a bounded, reviewable catalog patch. The returned paths are workspace-relative.
type ChangePlanner func(context.Context, ChangeRequest) (ChangePlan, error)

type ChangeRequest struct {
	CandidateID        string           `json:"candidate_id"`
	Adversary          string           `json:"adversary"`
	AdversaryMission   string           `json:"adversary_mission,omitempty"`
	ProposedRule       string           `json:"proposed_rule"`
	Evidence           string           `json:"evidence"`
	EvidencePRURL      string           `json:"evidence_pr_url,omitempty"`
	EvidenceCommentURL string           `json:"evidence_comment_url,omitempty"`
	EvidenceComment    string           `json:"evidence_comment"`
	EvidenceFile       string           `json:"evidence_file,omitempty"`
	EvidenceDiff       string           `json:"evidence_diff,omitempty"`
	EvidenceContext    string           `json:"evidence_source_context,omitempty"`
	ExistingAdversary  bool             `json:"existing_adversary"`
	Executable         bool             `json:"executable"`
	PolicyDriven       bool             `json:"policy_driven"`
	ManagedRuntime     int              `json:"managed_runtime,omitempty"`
	AllowOverlap       bool             `json:"allow_overlap,omitempty"`
	Files              []SourceFile     `json:"files"`
	CatalogPolicies    []SourceFile     `json:"catalog_policies,omitempty"`
	Progress           ProgressReporter `json:"-"`
	ValidationFeedback string           `json:"validation_feedback,omitempty"`
	LatestFeedback     string           `json:"latest_validation_feedback,omitempty"`
	RepairStage        string           `json:"repair_stage,omitempty"`
	PreviousPlanFiles  []string         `json:"previous_plan_files,omitempty"`
	PreviousPlan       *ChangePlan      `json:"previous_generated_plan,omitempty"`
	GenerationAttempt  int              `json:"generation_attempt,omitempty"`
	MaxGenerationTurns int              `json:"max_generation_attempts,omitempty"`
	MaxQualityTurns    int              `json:"max_quality_review_attempts,omitempty"`
	ValidationContract string           `json:"host_validation_contract,omitempty"`
}

type SourceFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

type ChangePlan struct {
	Summary  string       `json:"summary"`
	Files    []ChangeFile `json:"files"`
	Strategy string       `json:"-"`
}

const (
	StrategyModelBacked   = "model"
	StrategyDeterministic = "deterministic"
)

type ChangeFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// AlreadyCoveredError is a successful catalog deduplication outcome. Callers
// should remove the candidate from the active queue instead of presenting it
// as a failed generation attempt.
type AlreadyCoveredError struct {
	CandidateRule string
	Adversary     string
	RuleID        string
	Detail        string
}

func (e *AlreadyCoveredError) Error() string {
	owner := strings.Trim(strings.TrimSpace(e.Adversary+"/"+e.RuleID), "/")
	if owner == "" {
		owner = "the current catalog"
	}
	return fmt.Sprintf("%s is already covered by %s: %s", strings.TrimSpace(e.CandidateRule), owner, strings.TrimSpace(e.Detail))
}

// ApplyPlanned updates the current checkout with a substantive model-planned
// adversary change. It does not commit the result.
func ApplyPlanned(ctx context.Context, stateRoot, workspaceRoot string, cfg workspace.Config, id string, planner ChangePlanner) (returnErr error) {
	row, err := results.Get(stateRoot, id)
	if err != nil {
		return err
	}
	root, err := adversaryRoot(workspaceRoot, cfg)
	if err != nil {
		return err
	}
	rollback, err := snapshotCatalogChange(filepath.Join(root, row.Package), filepath.Join(workspaceRoot, "adversarylabs.yaml"))
	if err != nil {
		return fmt.Errorf("snapshot catalog before applying candidate: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			returnErr = errors.Join(returnErr, rollback())
		}
	}()
	target, _, err := applyPlannedCandidateWithProgressOptionsAndRunner(ctx, workspaceRoot, cfg, row, planner, nil, false, execCommand)
	if err != nil {
		return err
	}
	row.Status = results.StatusApplied
	row.AppliedAt = nowUTC()
	row.AppliedPath = target
	if err := results.SaveResult(stateRoot, row); err != nil {
		return err
	}
	committed = true
	return nil
}

func applyPlannedCandidate(ctx context.Context, workspaceRoot string, cfg workspace.Config, row results.Result, planner ChangePlanner) (string, error) {
	target, _, err := applyPlannedCandidateWithProgress(ctx, workspaceRoot, cfg, row, planner, nil)
	return target, err
}

func applyPlannedCandidateWithProgress(ctx context.Context, workspaceRoot string, cfg workspace.Config, row results.Result, planner ChangePlanner, report ProgressReporter) (string, string, error) {
	return applyPlannedCandidateWithProgressOptions(ctx, workspaceRoot, cfg, row, planner, report, false)
}

func applyPlannedCandidateWithProgressOptions(ctx context.Context, workspaceRoot string, cfg workspace.Config, row results.Result, planner ChangePlanner, report ProgressReporter, allowOverlap bool) (string, string, error) {
	return applyPlannedCandidateWithProgressOptionsAndRunner(ctx, workspaceRoot, cfg, row, planner, report, allowOverlap, nil)
}

func applyPlannedCandidateWithProgressOptionsAndRunner(ctx context.Context, workspaceRoot string, cfg workspace.Config, row results.Result, planner ChangePlanner, report ProgressReporter, allowOverlap bool, run commandRunner) (string, string, error) {
	emit := func(stage, state, detail string) {
		if report != nil {
			report(Progress{Stage: stage, State: state, Detail: detail})
		}
	}
	if planner == nil {
		return "", "", fmt.Errorf("catalog change generation needs a configured model provider")
	}
	if err := validateCandidate(row); err != nil {
		return "", "", err
	}
	root, err := adversaryRoot(workspaceRoot, cfg)
	if err != nil {
		return "", "", err
	}
	dir := filepath.Join(root, row.Package)
	_, policyErr := os.Stat(filepath.Join(dir, "README.md"))
	wasExisting := policyErr == nil
	if os.IsNotExist(policyErr) {
		if err := createAdversary(dir, row.Package, row.AdversaryMission); err != nil {
			return "", "", err
		}
	} else if policyErr != nil {
		return "", "", policyErr
	}
	if _, err := cataloginit.EnsureRunnableAdversary(dir, row.Package); err != nil {
		return "", "", fmt.Errorf("make catalog adversary runnable: %w", err)
	}
	request, root, dir, err := buildChangeRequest(workspaceRoot, cfg, row)
	if err != nil {
		return "", "", err
	}
	request.ExistingAdversary = wasExisting
	request.AllowOverlap = allowOverlap
	request.Progress = report
	attachHostValidationContract(&request)
	baseline, err := captureCatalogTree(dir)
	if err != nil {
		return "", "", fmt.Errorf("snapshot adversary before generated validation: %w", err)
	}
	restoreBaseline := func() error {
		if err := restoreCatalogTree(dir, baseline); err != nil {
			return fmt.Errorf("restore adversary before regeneration: %w", err)
		}
		return nil
	}
	var target, pullRequestTitle string
	for attempt := 0; attempt < maxPlanAttempts; attempt++ {
		request.GenerationAttempt = attempt + 1
		request.MaxGenerationTurns = maxPlanAttempts
		request.MaxQualityTurns = maxQualityReviewAttempts
		runtimeValidationFailed := false
		plan, err := planner(ctx, request)
		if err != nil {
			if attempt < maxPlanAttempts-1 && isRetryablePlanError(err) {
				request.LatestFeedback = err.Error()
				request.RepairStage = "plan_review"
				request.ValidationFeedback = err.Error() + ". Correct the rejected plan while preserving unaffected files and behavior."
				rememberPreviousPlan(&request, plan)
				continue
			}
			return "", "", fmt.Errorf("generate substantive adversary change: %w", err)
		}
		emit("test", "running", "Writing and checking regression cases")
		target, err = writeChangePlan(workspaceRoot, root, dir, row, request, plan)
		if err == nil {
			pullRequestTitle = strings.TrimSpace(plan.Summary)
			emit("test", "complete", "Regression cases added from the original review evidence")
			if run == nil {
				break
			}
			emit("validate", "running", "Building and testing the generated adversary")
			if validationErr := validateRunnablePackageAndSync(ctx, dir, run, request, plan); validationErr == nil {
				emit("validate", "complete", "Build, tests, validation, and package checks passed")
				break
			} else {
				err = validationErr
				runtimeValidationFailed = true
			}
		}
		retryable := isRetryablePlanError(err) || runtimeValidationFailed
		if attempt == maxPlanAttempts-1 || !retryable {
			if runtimeValidationFailed {
				emit("validate", "failed", commandFailureMessage(err.Error()))
				if restoreErr := restoreBaseline(); restoreErr != nil {
					return "", "", errors.Join(err, restoreErr)
				}
			}
			return "", "", err
		}
		if runtimeValidationFailed {
			emit("validate", "pending", commandFailureMessage(err.Error())+"; repairing and testing again")
		} else {
			emit("test", "pending", "Generated output needs repair; regenerating")
		}
		if err := restoreBaseline(); err != nil {
			return "", "", err
		}
		request.ValidationFeedback = err.Error() + ". Correct the rejected plan while preserving unaffected files and behavior."
		request.LatestFeedback = err.Error()
		if runtimeValidationFailed {
			request.RepairStage = "build_and_test"
		} else {
			request.RepairStage = "plan_validation"
		}
		rememberPreviousPlan(&request, plan)
	}
	if !request.ExistingAdversary {
		if err := addManifestEntry(filepath.Join(workspaceRoot, "adversarylabs.yaml"), row.Package, row.AdversaryMission); err != nil {
			return "", "", err
		}
	}
	return target, pullRequestTitle, nil
}

func attachHostValidationContract(request *ChangeRequest) {
	if request.ManagedRuntime == 1 && isSyncOnceCandidate(*request) {
		request.ValidationContract = syncOnceValidationContract(request.EvidenceFile)
	}
}

func rememberPreviousPlan(request *ChangeRequest, plan ChangePlan) {
	if len(plan.Files) == 0 {
		return
	}
	request.PreviousPlanFiles = request.PreviousPlanFiles[:0]
	for _, file := range plan.Files {
		request.PreviousPlanFiles = append(request.PreviousPlanFiles, file.Path)
	}
	previousPlan := plan
	previousPlan.Files = append([]ChangeFile(nil), plan.Files...)
	request.PreviousPlan = &previousPlan
}

func isRetryablePlanError(err error) bool {
	message := err.Error()
	return strings.HasPrefix(message, "generated change") ||
		strings.HasPrefix(message, "decode generated catalog change") ||
		strings.HasPrefix(message, "validate generated regression")
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
	files, executable, policyDriven, managedRuntime, err := readAdversaryFiles(workspaceRoot, dir)
	if err != nil {
		return ChangeRequest{}, "", "", err
	}
	catalogPolicies, err := readCatalogPolicies(workspaceRoot, root)
	if err != nil {
		return ChangeRequest{}, "", "", err
	}
	return ChangeRequest{
		CandidateID: row.ID, Adversary: row.Package, AdversaryMission: row.AdversaryMission,
		ProposedRule: row.ProposedRule, Evidence: evidenceURL(row), EvidencePRURL: row.PRURL, EvidenceCommentURL: row.CommentURL, EvidenceComment: row.Summary,
		EvidenceFile: row.File, EvidenceDiff: row.DiffHunk, ExistingAdversary: exists,
		Executable: executable, PolicyDriven: policyDriven, ManagedRuntime: managedRuntime, Files: files, CatalogPolicies: catalogPolicies,
	}, root, dir, nil
}

func readCatalogPolicies(workspaceRoot, root string) ([]SourceFile, error) {
	var files []SourceFile
	total := 0
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if path != root && (entry.Name() == "node_modules" || entry.Name() == "dist" || entry.Name() == ".git") {
				return filepath.SkipDir
			}
			return nil
		}
		relRoot, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		cleanRoot := filepath.ToSlash(relRoot)
		parts := strings.Split(cleanRoot, "/")
		include := len(parts) == 2 && parts[1] == "README.md"
		include = include || (len(parts) == 4 && parts[1] == "rules" && parts[3] == "rule.yaml")
		if !include || len(files) >= maxPolicyFiles || total >= maxPolicyBytes {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if len(raw) > 64<<10 || total+len(raw) > maxPolicyBytes {
			return nil
		}
		relWorkspace, err := filepath.Rel(workspaceRoot, path)
		if err != nil {
			return err
		}
		files = append(files, SourceFile{Path: filepath.ToSlash(relWorkspace), Content: string(raw)})
		total += len(raw)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read catalog policies: %w", err)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
}

func readAdversaryFiles(workspaceRoot, dir string) ([]SourceFile, bool, bool, int, error) {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil, false, false, 0, nil
	}
	var files []SourceFile
	total := 0
	executable := false
	policyDriven := false
	managedRuntime := 0
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
			var metadata struct {
				Runtime int `json:"adversarylabsCatalogRuntime"`
			}
			if json.Unmarshal(raw, &metadata) == nil {
				managedRuntime = metadata.Runtime
			}
		}
		files = append(files, SourceFile{Path: filepath.ToSlash(rel), Content: string(raw)})
		total += len(raw)
		return nil
	})
	if err != nil {
		return nil, false, false, 0, fmt.Errorf("read adversary source: %w", err)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, executable, policyDriven, managedRuntime, nil
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
	title := strings.Join(strings.Fields(plan.Summary), " ")
	if title == "" || utf8.RuneCountInString(title) > 120 || !strings.Contains(strings.ToLower(title), strings.ToLower(row.Package)) || strings.Contains(strings.ToLower(title), "review evidence") {
		return "", fmt.Errorf("generated change must include a specific pull-request title of at most 120 characters that names %s and does not say review evidence", row.Package)
	}
	if len(plan.Files) < 2 || len(plan.Files) > maxPlanFiles {
		return "", fmt.Errorf("generated change must contain an operative adversary edit and regression coverage (got %d files)", len(plan.Files))
	}
	adversaryRel, err := filepath.Rel(workspaceRoot, dir)
	if err != nil {
		return "", err
	}
	adversaryPrefix := filepath.ToSlash(adversaryRel) + "/"
	if request.ManagedRuntime == 1 && plan.Strategy != StrategyDeterministic {
		return writeManagedRulePlan(workspaceRoot, adversaryPrefix, row, plan)
	}
	existing := make(map[string]string, len(request.Files))
	for _, file := range request.Files {
		existing[file.Path] = file.Content
	}
	total, operative, regression := 0, "", ""
	implementation, nativeRegression := false, false
	newImplementation, runtimeRegression := false, false
	deterministicExtension := false
	deterministicReadsSources := false
	deterministicHardcodesEvidencePath := false
	deterministicHardcodesEvidenceLine := false
	deterministicTestProvidesSource := false
	evidencePathRegression := strings.TrimSpace(request.EvidenceFile) == ""
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
		changed := existing[clean] != file.Content
		if request.ManagedRuntime == 1 && plan.Strategy == StrategyDeterministic {
			if changed && relInAdversary == "src/index.ts" {
				return "", fmt.Errorf("generated deterministic change may not edit the managed src/index.ts runtime shell")
			}
			if strings.HasPrefix(relInAdversary, "rules/") {
				return "", fmt.Errorf("generated deterministic change may not add a model-backed rule bundle (%s)", clean)
			}
			if changed && strings.HasPrefix(relInAdversary, "src/") && (strings.Contains(file.Content, "ctx.model") || strings.Contains(file.Content, ".model.review")) {
				return "", fmt.Errorf("generated deterministic implementation may not call the model (%s)", clean)
			}
			if changed && relInAdversary == "src/deterministic.ts" {
				deterministicExtension = true
			}
			if changed && strings.HasPrefix(relInAdversary, "src/rules/") {
				deterministicReadsSources = deterministicReadsSources || strings.Contains(file.Content, "loadInScopeSources(")
				deterministicHardcodesEvidencePath = deterministicHardcodesEvidencePath || strings.TrimSpace(request.EvidenceFile) != "" && strings.Contains(file.Content, request.EvidenceFile)
				deterministicHardcodesEvidenceLine = deterministicHardcodesEvidenceLine || literalFindingLine.MatchString(file.Content)
			}
		}
		if request.PolicyDriven && (strings.HasPrefix(relInAdversary, "dist/") || relInAdversary == "adversary.yaml" || relInAdversary == "package.json" || relInAdversary == "package-lock.json") {
			return "", fmt.Errorf("policy-driven catalog training may not rewrite generated output or package metadata (%s)", clean)
		}
		base := filepath.Base(clean)
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
		} else if changed && isNativeTestPath(relInAdversary) {
			if _, existed := existing[clean]; existed {
				return "", fmt.Errorf("generated change replaced existing native test %s; add a new focused test file instead", clean)
			}
			if mutatesNodeFilesystemAPI(file.Content) {
				return "", fmt.Errorf("generated change native test %s attempts to replace read-only node:fs exports; use real temporary repository fixtures or an explicitly injected dependency", clean)
			}
			if request.ManagedRuntime == 1 && plan.Strategy == StrategyDeterministic && strings.Contains(file.Content, "/src/rules/") {
				return "", fmt.Errorf("generated deterministic native test %s bypasses rule registration by importing the helper directly; exercise it through createApp().run", clean)
			}
			regression = clean
			nativeRegression = true
			if strings.Contains(file.Content, "/src/index") && (request.ManagedRuntime != 1 || plan.Strategy != StrategyDeterministic || strings.Contains(file.Content, ".run(")) {
				runtimeRegression = true
			}
			if request.ManagedRuntime == 1 && plan.Strategy == StrategyDeterministic && managedRunSourceInput.MatchString(file.Content) {
				deterministicTestProvidesSource = true
			}
			if strings.Contains(file.Content, request.EvidenceFile) {
				evidencePathRegression = true
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
	if request.ManagedRuntime == 1 && plan.Strategy == StrategyDeterministic && !deterministicExtension {
		return "", fmt.Errorf("generated deterministic change did not register through src/deterministic.ts")
	}
	if request.ManagedRuntime == 1 && plan.Strategy == StrategyDeterministic && deterministicHardcodesEvidencePath && !deterministicReadsSources {
		return "", fmt.Errorf("generated deterministic rule is an evidence-path tripwire; inspect source content with loadInScopeSources before emitting a finding")
	}
	if request.ManagedRuntime == 1 && plan.Strategy == StrategyDeterministic && deterministicHardcodesEvidenceLine {
		return "", fmt.Errorf("generated deterministic rule hard-codes an evidence line; derive the finding line from the matched source")
	}
	if request.Executable && !nativeRegression {
		return "", fmt.Errorf("generated change did not add a focused native test file for the executable adversary")
	}
	if request.Executable && !evidencePathRegression {
		return "", fmt.Errorf("generated change native test does not exercise the exact evidence path %q", request.EvidenceFile)
	}
	if request.Executable && request.PolicyDriven && !runtimeRegression {
		return "", fmt.Errorf("generated change for policy-driven adversary did not add a native test that executes createApp().run through src/index")
	}
	if request.ManagedRuntime == 1 && plan.Strategy == StrategyDeterministic && runtimeRegression && !deterministicTestProvidesSource {
		return "", fmt.Errorf("generated deterministic native test calls createApp().run without the required input.source.path repository fixture")
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

var nodeFilesystemMutation = regexp.MustCompile(`(?m)\.\s*(?:readFileSync|readFile|readdirSync|readdir|statSync|lstatSync|existsSync)\s*=`)
var literalFindingLine = regexp.MustCompile(`(?m)\bline\s*:\s*[1-9][0-9]*\b`)
var managedRunSourceInput = regexp.MustCompile(`(?s)input\s*:\s*\{.*source\s*:\s*\{.*path\s*:`)

func mutatesNodeFilesystemAPI(content string) bool {
	return nodeFilesystemMutation.MatchString(content)
}

type managedRule struct {
	Version    int    `yaml:"version"`
	ID         string `yaml:"id"`
	Summary    string `yaml:"summary"`
	Guidance   string `yaml:"guidance"`
	Severity   string `yaml:"severity"`
	Confidence string `yaml:"confidence"`
	Evidence   string `yaml:"evidence"`
}

type managedCases struct {
	Version     int    `yaml:"version"`
	RuleID      string `yaml:"rule_id"`
	CandidateID string `yaml:"candidate_id"`
	Evidence    string `yaml:"evidence"`
	Cases       []struct {
		Name     string `yaml:"name"`
		Input    string `yaml:"review_input"`
		Expected string `yaml:"expected"`
		Reason   string `yaml:"reason"`
	} `yaml:"cases"`
}

var managedRuleID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

func writeManagedRulePlan(workspaceRoot, prefix string, row results.Result, plan ChangePlan) (string, error) {
	if len(plan.Files) != 2 {
		return "", fmt.Errorf("generated managed rule must contain exactly rule.yaml and cases.yaml (got %d files)", len(plan.Files))
	}
	var rulePath, casesPath string
	var rule managedRule
	var cases managedCases
	seen := map[string]bool{}
	for _, file := range plan.Files {
		clean := filepath.ToSlash(filepath.Clean(file.Path))
		if filepath.IsAbs(file.Path) || clean == ".." || strings.HasPrefix(clean, "../") || !strings.HasPrefix(clean, prefix+"rules/") || seen[clean] {
			return "", fmt.Errorf("generated managed rule contains unsafe path %q", file.Path)
		}
		seen[clean] = true
		rel := strings.TrimPrefix(clean, prefix)
		parts := strings.Split(rel, "/")
		if len(parts) != 3 || parts[0] != "rules" || !managedRuleID.MatchString(parts[1]) {
			return "", fmt.Errorf("managed rule files must be rules/<rule-id>/rule.yaml and cases.yaml")
		}
		switch parts[2] {
		case "rule.yaml":
			if err := yaml.Unmarshal([]byte(file.Content), &rule); err != nil {
				return "", fmt.Errorf("validate generated rule %s: %w", clean, err)
			}
			rulePath = clean
		case "cases.yaml":
			if err := yaml.Unmarshal([]byte(file.Content), &cases); err != nil {
				return "", fmt.Errorf("validate generated cases %s: %w", clean, err)
			}
			casesPath = clean
		default:
			return "", fmt.Errorf("managed rule may only generate rule.yaml and cases.yaml")
		}
	}
	if rulePath == "" || casesPath == "" || filepath.Dir(rulePath) != filepath.Dir(casesPath) {
		return "", fmt.Errorf("generated managed rule must colocate rule.yaml and cases.yaml")
	}
	ruleID := filepath.Base(filepath.Dir(rulePath))
	if rule.Version != 1 || rule.ID != ruleID || strings.TrimSpace(rule.Summary) == "" || strings.TrimSpace(rule.Guidance) == "" || rule.Evidence != evidenceURL(row) {
		return "", fmt.Errorf("generated rule must identify version 1, its directory id, guidance, and exact evidence URL")
	}
	if !map[string]bool{"low": true, "medium": true, "high": true, "critical": true}[rule.Severity] || !map[string]bool{"medium": true, "high": true}[rule.Confidence] {
		return "", fmt.Errorf("generated rule has unsupported severity or confidence")
	}
	if cases.Version != 1 || cases.RuleID != ruleID || cases.CandidateID != row.ID || cases.Evidence != evidenceURL(row) {
		return "", fmt.Errorf("generated cases must identify the rule, candidate, and exact evidence URL")
	}
	hasFinding, hasNoFinding := false, false
	for _, item := range cases.Cases {
		if strings.TrimSpace(item.Name) == "" || strings.TrimSpace(item.Input) == "" || strings.TrimSpace(item.Reason) == "" {
			return "", fmt.Errorf("every managed case needs name, review_input, expected, and reason")
		}
		if item.Expected == "finding" {
			hasFinding = true
		} else if item.Expected == "no_finding" {
			hasNoFinding = true
		} else {
			return "", fmt.Errorf("managed case expected must be finding or no_finding")
		}
	}
	if !hasFinding || !hasNoFinding {
		return "", fmt.Errorf("managed rule needs finding and no_finding cases")
	}
	ruleRaw, _ := yaml.Marshal(&rule)
	casesRaw, _ := yaml.Marshal(&cases)
	for path, content := range map[string][]byte{rulePath: ruleRaw, casesPath: casesRaw} {
		full := filepath.Join(workspaceRoot, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return "", err
		}
		if err := os.WriteFile(full, content, 0o644); err != nil {
			return "", err
		}
	}
	return filepath.Join(workspaceRoot, filepath.FromSlash(rulePath)), nil
}

func isNativeTestPath(path string) bool {
	clean := strings.ToLower(filepath.ToSlash(path))
	base := filepath.Base(clean)
	return strings.HasPrefix(clean, "test/") || strings.HasPrefix(clean, "tests/") ||
		strings.Contains(clean, "/__tests__/") || strings.Contains(base, ".test.") ||
		strings.Contains(base, ".spec.") || strings.HasSuffix(base, "_test.go")
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
	isolated, cleanup, err := prepareIsolatedRunnablePackage(dir)
	if err != nil {
		return err
	}
	defer cleanup()
	return validateRunnablePackageInPlace(ctx, isolated, run)
}

func validateRunnablePackageAndSync(ctx context.Context, dir string, run commandRunner, request ChangeRequest, plan ChangePlan) error {
	isolated, cleanup, err := prepareIsolatedRunnablePackage(dir)
	if err != nil {
		return err
	}
	defer cleanup()
	if err := injectHostValidationContracts(isolated, request, plan); err != nil {
		return err
	}
	if err := validateRunnablePackageInPlace(ctx, isolated, run); err != nil {
		return err
	}
	distSnapshot, err := captureCatalogTree(filepath.Join(isolated, "dist"))
	if err != nil {
		return fmt.Errorf("capture validated adversary build output: %w", err)
	}
	if distSnapshot.existed {
		if err := restoreCatalogTree(filepath.Join(dir, "dist"), distSnapshot); err != nil {
			return fmt.Errorf("synchronize validated adversary build output: %w", err)
		}
		if err := validateCompiledRelativeImports(dir); err != nil {
			return err
		}
	}
	return nil
}

// injectHostValidationContracts adds generator-owned behavioral checks only to
// the disposable validation copy. Model-authored tests are useful evidence, but
// they cannot be the sole acceptance boundary because a generated rule can
// accidentally weaken or omit the exact cases that would expose its defects.
func injectHostValidationContracts(dir string, request ChangeRequest, plan ChangePlan) error {
	if request.ManagedRuntime != 1 || plan.Strategy != StrategyDeterministic || !isSyncOnceCandidate(request) {
		return nil
	}
	path := filepath.Join(dir, "test", "adversary-host-sync-once-contract.test.ts")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("prepare generator-owned validation tests: %w", err)
	}
	if err := os.WriteFile(path, []byte(syncOnceValidationContract(request.EvidenceFile)), 0o644); err != nil {
		return fmt.Errorf("write generator-owned sync.Once validation contract: %w", err)
	}
	return nil
}

func isSyncOnceCandidate(request ChangeRequest) bool {
	haystack := strings.Join([]string{request.ProposedRule, request.EvidenceComment, request.EvidenceDiff, request.EvidenceContext}, "\n")
	return strings.Contains(haystack, "sync.Once") && (strings.Contains(haystack, ".Do") || strings.Contains(strings.ToLower(haystack), "initializ"))
}

func syncOnceValidationContract(evidenceFile string) string {
	evidenceFile = strings.TrimSpace(filepath.ToSlash(evidenceFile))
	if evidenceFile == "" || evidenceFile == "." || strings.HasPrefix(evidenceFile, "../") {
		evidenceFile = "fixture.go"
	}
	quotedPath, _ := json.Marshal(evidenceFile)
	return fmt.Sprintf(`// Generator-owned acceptance contract. This file exists only in the isolated
// validation copy and is never committed to the catalog.
import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { createApp } from "../src/index.ts";

const evidencePath = %s;

async function deterministicFindings(content: string) {
  const root = await mkdtemp(join(tmpdir(), "adversary-host-sync-once-"));
  const target = join(root, evidencePath);
  await mkdir(dirname(target), { recursive: true });
  await writeFile(target, content);
  const result = await createApp().run({ input: { source: { path: root } }, includeRawObservations: true });
  return result.findings.filter((finding) => finding.ruleId !== "private-policy");
}

test("host contract: detects multiline fallible sync.Once initialization with distinct bindings", async () => {
  const findings = await deterministicFindings(`+"`"+`package fixture
import "sync"
type Store interface{}
type Params struct{}
func NewStore(Params) (Store, error) { return nil, nil }
var param Params
var (
  objectStoreOnce sync.Once
  objectStore Store
  objectStoreErr error
)
func runtimeObjectStore() (Store, error) {
  objectStoreOnce.Do(func() {
    objectStore, objectStoreErr = NewStore(
        param,
      )
  })
  return objectStore, objectStoreErr
}
`+"`"+`);
  assert.equal(findings.length, 1, "the evidence-shaped multiline initialization must be reported");
  assert.equal(findings[0]?.evidence[0]?.location?.file, evidencePath);
});

test("host contract: rejects a custom Do receiver despite another sync.Once declaration", async () => {
  const findings = await deterministicFindings(`+"`"+`package fixture
import "sync"
type Store interface{}
type customOnce struct{}
func (customOnce) Do(fn func()) { fn() }
func NewStore() (Store, error) { return nil, nil }
var objectStoreOnce customOnce
var objectStore Store
var objectStoreErr error
var unrelatedOnce sync.Once
func runtimeObjectStore() (Store, error) {
  objectStoreOnce.Do(func() { objectStore, objectStoreErr = NewStore() })
  return objectStore, objectStoreErr
}
`+"`"+`);
  assert.equal(findings.length, 0, "an unrelated sync.Once must not bless a custom receiver");
});

test("host contract: rejects an Err-named non-error binding", async () => {
  const findings = await deterministicFindings(`+"`"+`package fixture
import "sync"
type Store interface{}
func NewStore() (Store, int) { return nil, 0 }
var objectStoreOnce sync.Once
var objectStore Store
var objectStoreErr int
func runtimeObjectStore() (Store, int) {
  objectStoreOnce.Do(func() { objectStore, objectStoreErr = NewStore() })
  return objectStore, objectStoreErr
}
`+"`"+`);
  assert.equal(findings.length, 0, "an identifier suffix is not proof that the binding has Go error type");
});

test("host contract: rejects parameter shadowing and selector receivers", async () => {
  const findings = await deterministicFindings(`+"`"+`package fixture
import "sync"
type Store interface{}
type customOnce struct{}
func (customOnce) Do(fn func()) { fn() }
func NewStore() (Store, error) { return nil, nil }
var objectStoreOnce sync.Once
var objectStore Store
var objectStoreErr error
type holderType struct { objectStoreOnce customOnce }
func parameter(objectStoreOnce customOnce) (Store, error) {
  objectStoreOnce.Do(func() { objectStore, objectStoreErr = NewStore() })
  return objectStore, objectStoreErr
}
func selector(holder holderType) (Store, error) {
  holder.objectStoreOnce.Do(func() { objectStore, objectStoreErr = NewStore() })
  return objectStore, objectStoreErr
}
`+"`"+`);
  assert.equal(findings.length, 0, "shadowed identifiers and selector fields are not the package sync.Once binding");
});

test("host contract: rejects a fallible constructor outside the Do callback", async () => {
  const findings = await deterministicFindings(`+"`"+`package fixture
import "sync"
type Store interface{}
func NewStore() (Store, error) { return nil, nil }
var objectStoreOnce sync.Once
var ready bool
func runtimeObjectStore() (Store, error) {
  objectStoreOnce.Do(func() { ready = true })
  objectStore, objectStoreErr := NewStore()
  return objectStore, objectStoreErr
}
`+"`"+`);
  assert.equal(findings.length, 0, "the fallible assignment must occur inside the sync.Once callback");
});

test("host contract: rejects declarations borrowed from an earlier function", async () => {
  const findings = await deterministicFindings(`+"`"+`package fixture
import "sync"
type Store interface{}
type customOnce struct{}
func (customOnce) Do(fn func()) { fn() }
func NewStore() (Store, error) { return nil, nil }
func unrelated() { var poisonedOnce sync.Once; _ = poisonedOnce }
var poisonedOnce customOnce
var cached Store
var cachedErr error
func runtimeObjectStore() (Store, error) {
  poisonedOnce.Do(func() { cached, cachedErr = NewStore() })
  return cached, cachedErr
}
`+"`"+`);
  assert.equal(findings.length, 0, "a declaration inside another function is not a package binding");
});

test("host contract: requires the tuple assignment RHS itself to be a call", async () => {
  const findings = await deterministicFindings(`+"`"+`package fixture
import "sync"
type Store interface{}
func NewStore() (Store, error) { return nil, nil }
var once sync.Once
var cached, other Store
var cachedErr, otherErr error
func runtimeObjectStore() (Store, error) {
  once.Do(func() {
    cached, cachedErr = other, otherErr
    NewStore()
  })
  return cached, cachedErr
}
`+"`"+`);
  assert.equal(findings.length, 0, "an unrelated call must not make a value assignment look fallible");
});

test("host contract: rejects short-declaration shadowing", async () => {
  const findings = await deterministicFindings(`+"`"+`package fixture
import "sync"
type Store interface{}
type customOnce struct{}
func (customOnce) Do(fn func()) { fn() }
func NewStore() (Store, error) { return nil, nil }
var once sync.Once
var cached Store
var cachedErr error
func runtimeObjectStore() (Store, error) {
  once := customOnce{}
  once.Do(func() { cached, cachedErr = NewStore() })
  return cached, cachedErr
}
`+"`"+`);
  assert.equal(findings.length, 0, "a short declaration shadows the package sync.Once");
});

test("host contract: rejects an error declaration borrowed from another function", async () => {
  const findings = await deterministicFindings(`+"`"+`package fixture
import "sync"
type Store interface{}
func NewStore() (Store, int) { return nil, 0 }
func unrelated() { var cachedErr error; _ = cachedErr }
var once sync.Once
var cached Store
var cachedErr int
func runtimeObjectStore() (Store, int) {
  once.Do(func() { cached, cachedErr = NewStore() })
  return cached, cachedErr
}
`+"`"+`);
  assert.equal(findings.length, 0, "an error binding in another function is outside the applicable scope");
});

test("host contract: finds a candidate after an earlier anonymous function", async () => {
  const findings = await deterministicFindings(`+"`"+`package fixture
import "sync"
type Store interface{}
func NewStore() (Store, error) { return nil, nil }
var once sync.Once
var cached Store
var cachedErr error
func runtimeObjectStore() (Store, error) {
  _ = func() bool { return true }
  once.Do(func() { cached, cachedErr = NewStore() })
  return cached, cachedErr
}
`+"`"+`);
  assert.equal(findings.length, 1, "an earlier anonymous function must not replace the enclosing function");
});

test("host contract: reports every matching function in one file", async () => {
  const findings = await deterministicFindings(`+"`"+`package fixture
import "sync"
type Store interface{}
func NewStore() (Store, error) { return nil, nil }
var firstOnce sync.Once
var first Store
var firstErr error
var secondOnce sync.Once
var second Store
var secondErr error
func firstStore() (Store, error) {
  firstOnce.Do(func() { first, firstErr = NewStore() })
  return first, firstErr
}
func secondStore() (Store, error) {
  secondOnce.Do(func() { second, secondErr = NewStore() })
  return second, secondErr
}
`+"`"+`);
  assert.equal(findings.length, 2, "each independent poisoned initializer must produce a finding");
});
`, string(quotedPath))
}

func prepareIsolatedRunnablePackage(dir string) (string, func(), error) {
	snapshot, err := captureCatalogTreeSkipping(dir, func(name string) bool {
		return name == "node_modules" || name == ".adversary" || name == ".git"
	})
	if err != nil {
		return "", nil, fmt.Errorf("prepare isolated adversary validation: %w", err)
	}
	tempRoot, err := os.MkdirTemp("", "adversary-catalog-validate-")
	if err != nil {
		return "", nil, fmt.Errorf("prepare isolated adversary validation: %w", err)
	}
	isolated := filepath.Join(tempRoot, "package")
	if err := restoreCatalogTree(isolated, snapshot); err != nil {
		_ = os.RemoveAll(tempRoot)
		return "", nil, fmt.Errorf("prepare isolated adversary validation: %w", err)
	}
	return isolated, func() { _ = os.RemoveAll(tempRoot) }, nil
}

func validateCompiledRelativeImports(packageDir string) error {
	dist := filepath.Join(packageDir, "dist")
	return filepath.WalkDir(dist, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".js") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, match := range sourceImportPattern.FindAllStringSubmatch(string(raw), -1) {
			base := filepath.Clean(filepath.Join(filepath.Dir(path), filepath.FromSlash(match[1])))
			candidates := []string{base}
			if filepath.Ext(base) == "" {
				candidates = append(candidates, base+".js", filepath.Join(base, "index.js"))
			}
			found := false
			for _, candidate := range candidates {
				rel, relErr := filepath.Rel(packageDir, candidate)
				if relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
					continue
				}
				if info, statErr := os.Stat(candidate); statErr == nil && !info.IsDir() {
					found = true
					break
				}
			}
			if !found {
				rel, _ := filepath.Rel(packageDir, path)
				return fmt.Errorf("generated committed runtime %s imports missing module %q", filepath.ToSlash(rel), match[1])
			}
		}
		return nil
	})
}

func validateRunnablePackageInPlace(ctx context.Context, dir string, run commandRunner) error {
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
