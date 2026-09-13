package catalogapply

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

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
	CandidateID       string       `json:"candidate_id"`
	Adversary         string       `json:"adversary"`
	AdversaryMission  string       `json:"adversary_mission,omitempty"`
	ProposedRule      string       `json:"proposed_rule"`
	Evidence          string       `json:"evidence"`
	EvidenceComment   string       `json:"evidence_comment"`
	EvidenceFile      string       `json:"evidence_file,omitempty"`
	EvidenceDiff      string       `json:"evidence_diff,omitempty"`
	ExistingAdversary bool         `json:"existing_adversary"`
	Executable        bool         `json:"executable"`
	Files             []SourceFile `json:"files"`
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
	request, root, dir, err := buildChangeRequest(workspaceRoot, cfg, row)
	if err != nil {
		return "", err
	}
	plan, err := planner(ctx, request)
	if err != nil {
		return "", fmt.Errorf("generate substantive adversary change: %w", err)
	}
	target, err := writeChangePlan(workspaceRoot, root, dir, row, request, plan)
	if err != nil {
		return "", err
	}
	if !request.ExistingAdversary {
		if err := addManifestEntry(filepath.Join(workspaceRoot, "adversarylabs.yaml"), row.Package, row.AdversaryMission); err != nil {
			return "", err
		}
	}
	return target, nil
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
	files, executable, err := readAdversaryFiles(workspaceRoot, dir)
	if err != nil {
		return ChangeRequest{}, "", "", err
	}
	return ChangeRequest{
		CandidateID: row.ID, Adversary: row.Package, AdversaryMission: row.AdversaryMission,
		ProposedRule: row.ProposedRule, Evidence: evidenceURL(row), EvidenceComment: row.Summary,
		EvidenceFile: row.File, EvidenceDiff: row.DiffHunk, ExistingAdversary: exists,
		Executable: executable, Files: files,
	}, root, dir, nil
}

func readAdversaryFiles(workspaceRoot, dir string) ([]SourceFile, bool, error) {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil, false, nil
	}
	var files []SourceFile
	total := 0
	executable := false
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
		if entry.Type()&os.ModeSymlink != 0 || strings.HasSuffix(entry.Name(), ".lock") {
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
		files = append(files, SourceFile{Path: filepath.ToSlash(rel), Content: string(raw)})
		total += len(raw)
		return nil
	})
	if err != nil {
		return nil, false, fmt.Errorf("read adversary source: %w", err)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, executable, nil
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
	seen := map[string]bool{}
	for _, file := range plan.Files {
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
		base := filepath.Base(clean)
		changed := existing[clean] != file.Content
		if changed && (base == "README.md" || relInAdversary == "agent/scope.md" || relInAdversary == "docs/scope.md") {
			operative = clean
		}
		if changed && strings.HasPrefix(relInAdversary, "src/") {
			implementation = true
		}
		if changed && strings.HasPrefix(relInAdversary, "tests/") && (strings.HasSuffix(clean, ".yaml") || strings.HasSuffix(clean, ".yml")) {
			if err := validateRegression([]byte(file.Content), row); err != nil {
				return "", fmt.Errorf("validate generated regression %s: %w", clean, err)
			}
			regression = clean
		} else if changed && (strings.Contains(strings.ToLower(base), "test") || strings.Contains(strings.ToLower(base), "spec")) {
			regression = clean
			nativeRegression = true
		}
	}
	if operative == "" {
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

func validateRegression(raw []byte, row results.Result) error {
	var spec regressionSpec
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		return err
	}
	if spec.Version != 1 || spec.CandidateID != row.ID || spec.Adversary != row.Package || spec.Evidence != evidenceURL(row) || strings.TrimSpace(spec.Rule) == "" {
		return fmt.Errorf("regression must identify version 1, candidate %s, adversary %s, and its rule", row.ID, row.Package)
	}
	hasFinding, hasNoFinding := false, false
	for _, c := range spec.Cases {
		if strings.TrimSpace(c.Name) == "" || strings.TrimSpace(c.Input) == "" || strings.TrimSpace(c.Reason) == "" {
			return fmt.Errorf("every regression case needs name, review_input, expected, and reason")
		}
		switch c.Expected {
		case "finding":
			hasFinding = true
		case "no_finding":
			hasNoFinding = true
		default:
			return fmt.Errorf("expected must be finding or no_finding")
		}
	}
	if !hasFinding || !hasNoFinding {
		return fmt.Errorf("regression needs both a finding and a no_finding case")
	}
	return nil
}

var nowUTC = func() time.Time { return time.Now().UTC() }
