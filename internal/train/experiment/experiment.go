package experiment

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/adversarylabs/adversary/internal/train/optimizer"
	"github.com/adversarylabs/adversary/internal/train/runner"
	"github.com/adversarylabs/adversary/internal/train/score"
)

// Report is the base-vs-candidate report for human decision.
type Report struct {
	ExperimentID        string           `json:"experiment_id"`
	TargetAdversary     string           `json:"target_adversary"`
	Status              string           `json:"status"`   // needs-human-review | accepted | rejected
	Decision            string           `json:"decision"` // empty | accept | reject — human fills
	Hypothesis          string           `json:"hypothesis"`
	BaseScorecard       *score.Scorecard `json:"base_scorecard"`
	CandidateScorecard  *score.Scorecard `json:"candidate_scorecard"`
	BaseFailures        int              `json:"base_failures"`
	CandidateFailures   int              `json:"candidate_failures"`
	OriginatingImproved bool             `json:"originating_improved"`
	DeltaRecall         float64          `json:"delta_important_recall"`
	DeltaPrecision      float64          `json:"delta_precision"`
	// CandidateScoresMode is "remeasured" when candidate reviews were re-run and judged,
	// or "identical_to_base" when no independent candidate measurement was available
	// (candidate metrics copy base; deltas are zero; not an improvement claim).
	CandidateScoresMode string      `json:"candidate_scores_mode"`
	CandidateBuild      BuildResult `json:"candidate_build"`
	Notes               string      `json:"notes,omitempty"`
	GeneratedAt         time.Time   `json:"generated_at"`
	// Explicitly no auto_merge / auto_publish fields — human only.
}

// BuildResult records candidate packaging.
type BuildResult struct {
	OK             bool   `json:"ok"`
	Method         string `json:"method"` // copy-improvement | adversary-pack | blocked
	WorktreePath   string `json:"worktree_path,omitempty"`
	ArtifactPath   string `json:"artifact_path,omitempty"`
	Error          string `json:"error,omitempty"`
	Classification string `json:"classification,omitempty"`
	NextAction     string `json:"next_action,omitempty"`
}

// AssembleReport builds a human-decidable experiment report from base/candidate scores.
// candidateScoresMode must be "remeasured" or "identical_to_base".
func AssembleReport(rec *optimizer.ExperimentRecord, base, cand *score.Scorecard, build BuildResult, candidateScoresMode string) *Report {
	if candidateScoresMode == "" {
		candidateScoresMode = "identical_to_base"
	}
	r := &Report{
		ExperimentID:        rec.ID,
		TargetAdversary:     rec.TargetAdversary,
		Status:              "needs-human-review",
		Decision:            "", // human only
		Hypothesis:          rec.Hypothesis,
		BaseScorecard:       base,
		CandidateScorecard:  cand,
		CandidateBuild:      build,
		CandidateScoresMode: candidateScoresMode,
		GeneratedAt:         time.Now().UTC(),
	}
	if base != nil {
		r.BaseFailures = base.FailureCount
	}
	if cand != nil {
		r.CandidateFailures = cand.FailureCount
	}
	if candidateScoresMode == "identical_to_base" {
		// Honest: no independent measurement — zero deltas, not improved.
		r.DeltaRecall = 0
		r.DeltaPrecision = 0
		r.OriginatingImproved = false
		if cand != nil && base != nil {
			r.CandidateFailures = base.FailureCount
		}
		r.Notes = "Candidate scores identical to base (no independent re-measure). Decision left empty for human accept/reject. Factory does not auto-merge or publish."
		return r
	}
	if base != nil && cand != nil {
		r.DeltaRecall = cand.ImportantConcernRecall - base.ImportantConcernRecall
		r.DeltaPrecision = cand.Precision - base.Precision
		r.OriginatingImproved = cand.FailureCount < base.FailureCount || r.DeltaRecall > 0
	}
	r.Notes = "Candidate scores remeasured by re-running reviews. Decision left empty for human accept/reject. Factory does not auto-merge or publish."
	return r
}

// CopyScorecardAsCandidate returns a deep copy labeled as candidate with no metric changes.
// Used when an independent candidate re-run is not available — never fabricates deltas.
func CopyScorecardAsCandidate(base *score.Scorecard) *score.Scorecard {
	if base == nil {
		return nil
	}
	raw, err := json.Marshal(base)
	if err != nil {
		return nil
	}
	var cand score.Scorecard
	if err := json.Unmarshal(raw, &cand); err != nil {
		return nil
	}
	cand.ReviewerID = base.ReviewerID + "-candidate"
	return &cand
}

// ApplyProposalToWorktree copies the adversary source and applies the improvement snippet.
// It does not modify the canonical checkout; work happens under dataRoot/worktrees.
// The source package path is locked so concurrent package runs cannot race a copy.
func ApplyProposalToWorktree(dataRoot, adversarySource, improvementMarkdown, experimentID string) (BuildResult, error) {
	if adversarySource == "" {
		return BuildResult{
			OK:             false,
			Method:         "blocked",
			Classification: "missing-source",
			Error:          "adversary source path not configured",
			NextAction:     "set engineering-review local_path in config/adversaries.yaml or pass --source",
		}, nil
	}
	unlock := runner.LockLocalPackage(adversarySource)
	defer unlock()
	if _, err := os.Stat(adversarySource); err != nil {
		return BuildResult{
			OK:             false,
			Method:         "blocked",
			Classification: "missing-source",
			Error:          err.Error(),
			NextAction:     "clone or point local_path at engineering-review-adversary",
		}, nil
	}
	wt := filepath.Join(dataRoot, "worktrees", experimentID)
	if err := os.RemoveAll(wt); err != nil {
		return BuildResult{}, err
	}
	// Prefer git worktree if source is a git repo; else copy.
	if _, err := os.Stat(filepath.Join(adversarySource, ".git")); err == nil {
		cmd := exec.Command("git", "worktree", "add", "--detach", wt, "HEAD")
		cmd.Dir = adversarySource
		if out, err := cmd.CombinedOutput(); err != nil {
			if err2 := copyDir(adversarySource, wt); err2 != nil {
				return BuildResult{
					OK:             false,
					Method:         "blocked",
					Classification: "failed",
					Error:          fmt.Sprintf("worktree: %v (%s); copy: %v", err, string(out), err2),
				}, nil
			}
		}
	} else {
		if err := copyDir(adversarySource, wt); err != nil {
			return BuildResult{OK: false, Method: "blocked", Error: err.Error()}, nil
		}
	}
	impPath := filepath.Join(wt, "FACTORY_IMPROVEMENT.md")
	if err := os.WriteFile(impPath, []byte(improvementMarkdown), 0o644); err != nil {
		return BuildResult{}, err
	}
	artifactDir := filepath.Join(dataRoot, "artifacts", "adversaries", "engineering-review", experimentID)
	_ = os.MkdirAll(artifactDir, 0o755)
	pack := BuildResult{
		OK:           true,
		Method:       "copy-improvement",
		WorktreePath: wt,
		ArtifactPath: impPath,
	}
	if path, err := exec.LookPath("adversary"); err == nil {
		cmd := exec.Command(path, "pack", ".")
		cmd.Dir = wt
		if out, err := cmd.CombinedOutput(); err != nil {
			pack.Error = fmt.Sprintf("pack optional failed: %v (%s)", err, truncate(string(out), 200))
		} else {
			pack.Method = "adversary-pack"
			pack.ArtifactPath = artifactDir
		}
	}
	return pack, nil
}

func copyDir(src, dst string) error {
	if _, err := exec.LookPath("rsync"); err == nil {
		cmd := exec.Command("rsync", "-a", "--exclude", "node_modules", "--exclude", ".git", src+"/", dst+"/")
		return cmd.Run()
	}
	cmd := exec.Command("cp", "-R", src, dst)
	return cmd.Run()
}

// SaveReport writes the experiment report.
func SaveReport(dir string, r *Report) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "report.json"), raw, 0o644); err != nil {
		return err
	}
	summary := fmt.Sprintf(`Experiment %s — NEEDS HUMAN REVIEW

Target: %s
Hypothesis: %s

Candidate scores mode: %s
Base failures: %d
Candidate failures: %d
Delta important recall: %+.3f
Delta precision: %+.3f
Originating improved: %v

Candidate build: ok=%v method=%s
Decision: (unset — run factory experiment decide --accept|--reject)

No auto-merge. No auto-publish.
`, r.ExperimentID, r.TargetAdversary, truncate(r.Hypothesis, 200),
		r.CandidateScoresMode,
		r.BaseFailures, r.CandidateFailures, r.DeltaRecall, r.DeltaPrecision, r.OriginatingImproved,
		r.CandidateBuild.OK, r.CandidateBuild.Method)
	return os.WriteFile(filepath.Join(dir, "report.txt"), []byte(summary), 0o644)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// LoadRecord loads an experiment record JSON.
func LoadRecord(path string) (*optimizer.ExperimentRecord, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rec optimizer.ExperimentRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}
