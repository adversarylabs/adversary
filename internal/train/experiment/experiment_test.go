package experiment

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/adversarylabs/adversary/internal/train/judge"
	"github.com/adversarylabs/adversary/internal/train/optimizer"
	"github.com/adversarylabs/adversary/internal/train/score"
)

func TestAssembleReportIdenticalToBaseNoFakeDeltas(t *testing.T) {
	rec := &optimizer.ExperimentRecord{
		ID:              "exp-1",
		TargetAdversary: "engineering-review",
		Hypothesis:      "generalized failure mode about missed concerns",
		Status:          "proposed",
	}
	base := &score.Scorecard{
		ReviewerID:             "engineering-review",
		CaseCount:              2,
		ImportantConcernRecall: 0.4,
		Precision:              0.5,
		FailureCount:           5,
		Failures: []judge.Failure{
			{CaseID: "c1", Kind: "missed-concern", Detail: "missed"},
		},
	}
	cand := CopyScorecardAsCandidate(base)
	rep := AssembleReport(rec, base, cand, BuildResult{OK: true, Method: "copy-improvement"}, "identical_to_base")
	if rep.Decision != "" {
		t.Fatalf("decision must be empty for human: %q", rep.Decision)
	}
	if rep.Status != "needs-human-review" {
		t.Fatalf("status=%s", rep.Status)
	}
	if rep.CandidateScoresMode != "identical_to_base" {
		t.Fatalf("mode=%s", rep.CandidateScoresMode)
	}
	if rep.DeltaRecall != 0 || rep.DeltaPrecision != 0 {
		t.Fatalf("identical_to_base must not invent deltas: recall=%v prec=%v", rep.DeltaRecall, rep.DeltaPrecision)
	}
	if rep.OriginatingImproved {
		t.Fatal("identical_to_base must not claim originating_improved")
	}
	if rep.CandidateFailures != rep.BaseFailures {
		t.Fatalf("failures base=%d cand=%d", rep.BaseFailures, rep.CandidateFailures)
	}
	dir := t.TempDir()
	if err := SaveReport(dir, rep); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var loaded Report
	if err := json.Unmarshal(raw, &loaded); err != nil {
		t.Fatal(err)
	}
	if loaded.OriginatingImproved || loaded.DeltaRecall != 0 {
		t.Fatalf("loaded invented improvement: %+v", loaded)
	}
}

func TestAssembleReportRemeasuredUsesRealDeltas(t *testing.T) {
	rec := &optimizer.ExperimentRecord{ID: "exp-2", TargetAdversary: "engineering-review", Hypothesis: "h"}
	base := &score.Scorecard{ReviewerID: "engineering-review", FailureCount: 4, ImportantConcernRecall: 0.2, Precision: 0.5}
	cand := &score.Scorecard{ReviewerID: "engineering-review-candidate", FailureCount: 2, ImportantConcernRecall: 0.5, Precision: 0.6}
	rep := AssembleReport(rec, base, cand, BuildResult{OK: true}, "remeasured")
	if rep.CandidateScoresMode != "remeasured" {
		t.Fatal(rep.CandidateScoresMode)
	}
	if rep.DeltaRecall != 0.3 {
		t.Fatalf("delta recall=%v", rep.DeltaRecall)
	}
	if !rep.OriginatingImproved {
		t.Fatal("expected originating improved when failures drop")
	}
}

func TestApplyProposalBlockedMissingSource(t *testing.T) {
	build, err := ApplyProposalToWorktree(t.TempDir(), "/no/such/adversary/source", "# improvement", "exp-x")
	if err != nil {
		t.Fatal(err)
	}
	if build.OK || build.Method != "blocked" {
		t.Fatalf("%+v", build)
	}
	if build.Classification != "missing-source" {
		t.Fatalf("class=%s", build.Classification)
	}
}

func TestCopyScorecardAsCandidatePreservesMetrics(t *testing.T) {
	base := &score.Scorecard{
		ReviewerID:             "engineering-review",
		ImportantConcernRecall: 0.33,
		Precision:              0.5,
		FailureCount:           7,
	}
	cand := CopyScorecardAsCandidate(base)
	if cand.ImportantConcernRecall != base.ImportantConcernRecall || cand.Precision != base.Precision || cand.FailureCount != base.FailureCount {
		t.Fatalf("copy mutated metrics: %+v vs %+v", cand, base)
	}
	if cand.ReviewerID == base.ReviewerID {
		t.Fatal("candidate reviewer id should differ")
	}
}
