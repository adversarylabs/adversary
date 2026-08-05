package pipeline

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/adversarylabs/adversary/internal/train/receipt"
)

func TestFixtureSliceEndToEnd(t *testing.T) {
	// Locate repo root (module root with fixtures).
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// internal/train/pipeline -> internal/train (fixtures live here)
	repoRoot := filepath.Clean(filepath.Join(wd, ".."))
	if _, err := os.Stat(filepath.Join(repoRoot, "fixtures", "cases")); err != nil {
		t.Fatalf("fixtures not found at %s: %v", repoRoot, err)
	}
	dataRoot := t.TempDir()
	// Point source at sibling engineering-review if present (optional).
	src := filepath.Join(filepath.Dir(repoRoot), "engineering-review-adversary")
	if _, err := os.Stat(src); err != nil {
		src = ""
	}
	res, err := Run(Options{
		DataRoot:        dataRoot,
		RepoRoot:        repoRoot,
		Fixture:         true,
		AdversarySource: src,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Scorecard == nil {
		t.Fatal("missing scorecard")
	}
	if res.Scorecard.FailureCount < 1 {
		t.Fatalf("expected failures, got %d", res.Scorecard.FailureCount)
	}
	if len(res.Hypotheses) < 1 {
		t.Fatal("expected critic hypotheses")
	}
	if res.Proposal == nil || res.Proposal.PatchPath == "" {
		t.Fatal("expected optimizer proposal with patch")
	}
	if _, err := os.Stat(res.Proposal.PatchPath); err != nil {
		t.Fatal(err)
	}
	if res.Report == nil {
		t.Fatal("missing experiment report")
	}
	if res.Report.Decision != "" {
		t.Fatalf("decision must be human-unset, got %q", res.Report.Decision)
	}
	if res.Report.Status != "needs-human-review" {
		t.Fatalf("status=%s", res.Report.Status)
	}
	// Candidate scores must not fabricate improvement when not remeasured.
	switch res.Report.CandidateScoresMode {
	case "identical_to_base":
		if res.Report.OriginatingImproved || res.Report.DeltaRecall != 0 || res.Report.DeltaPrecision != 0 {
			t.Fatalf("identical_to_base invented improvement: improved=%v dRecall=%v dPrec=%v",
				res.Report.OriginatingImproved, res.Report.DeltaRecall, res.Report.DeltaPrecision)
		}
	case "remeasured":
		// deltas may be non-zero only from real re-judge
	default:
		t.Fatalf("unexpected candidate_scores_mode %q", res.Report.CandidateScoresMode)
	}
	// Receipt present and verifiable
	rpath := filepath.Join(dataRoot, "runs", res.RunID, "receipt.json")
	raw, err := os.ReadFile(rpath)
	if err != nil {
		t.Fatal(err)
	}
	var rcpt receipt.Receipt
	if err := json.Unmarshal(raw, &rcpt); err != nil {
		t.Fatal(err)
	}
	if err := receipt.Verify(&rcpt); err != nil {
		t.Fatal(err)
	}
	if rcpt.FinalStatus != "success" && rcpt.FinalStatus != "partial" {
		t.Fatalf("final_status=%s", rcpt.FinalStatus)
	}
	// No auto-merge markers
	if rcpt.Notes != "" && (contains(rcpt.Notes, "merged") || contains(rcpt.Notes, "published")) {
		t.Fatalf("unexpected merge/publish notes: %s", rcpt.Notes)
	}
	// Scorecard artifact
	if _, err := os.Stat(filepath.Join(dataRoot, "runs", res.RunID, "reports", "scorecard.json")); err != nil {
		t.Fatal(err)
	}
	// Human-readable story report
	if res.HumanReport == nil || res.HumanReport.READMEPath == "" {
		t.Fatal("expected human report path")
	}
	story, err := os.ReadFile(res.HumanReport.READMEPath)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(string(story), "Bottom line") || !contains(string(story), "What the human reviewer said") {
		t.Fatalf("story incomplete: %s", res.HumanReport.READMEPath)
	}
	if res.HumanReport.Verdict != "GOOD" && res.HumanReport.Verdict != "MIXED" && res.HumanReport.Verdict != "BAD" {
		t.Fatalf("unexpected verdict %q", res.HumanReport.Verdict)
	}
	if !contains(res.Message, "BOTTOM LINE") {
		t.Fatalf("CLI message should be plain English, got: %s", res.Message)
	}
	// Projection isolation already unit-tested; ensure materialized reviewer dir has no labels
	mat := filepath.Join(dataRoot, "runs", res.RunID, "materialized")
	_ = filepath.Walk(mat, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		b, _ := os.ReadFile(path)
		s := string(b)
		if contains(s, "expected_concerns") || contains(s, "c-leak-1") {
			t.Errorf("label leak in materialized %s", path)
		}
		return nil
	})
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		(len(s) > 0 && (stringIndex(s, sub) >= 0)))
}

func stringIndex(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
