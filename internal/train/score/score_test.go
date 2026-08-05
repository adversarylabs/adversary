package score

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/adversarylabs/adversary/internal/train/judge"
)

func TestAggregateAndSave(t *testing.T) {
	j := &judge.ReviewJudgment{
		ReviewerID:      "go-concurrency",
		ExpectedMatched: []string{"c1"},
		ExpectedMissed:  []string{"c2"},
		Findings: []judge.FindingJudgment{
			{FindingID: "f1", Valid: true, SupportedByEvidence: true},
			{FindingID: "f2", Valid: false, SupportedByEvidence: false},
		},
	}
	fails := []judge.Failure{
		{CaseID: "case-1", Kind: "missed-concern", ConcernID: "c2", ReviewerID: "go-concurrency"},
		{CaseID: "case-1", Kind: "false-positive", FindingID: "f2", ReviewerID: "go-concurrency"},
	}
	sc := Aggregate("go-concurrency", map[string]*judge.ReviewJudgment{"case-1": j}, fails)
	if sc == nil {
		t.Fatal("nil")
	}
	if sc.FailureCount < 1 {
		t.Fatalf("failures %d", sc.FailureCount)
	}
	text := FormatText(sc)
	if text == "" {
		t.Fatal("empty format")
	}
	dir := t.TempDir()
	if err := Save(dir, sc); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"scorecard.json", "scorecard.txt", "failures.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAggregateEmpty(t *testing.T) {
	sc := Aggregate("x", nil, nil)
	if sc == nil || sc.ReviewerID != "x" {
		t.Fatalf("%+v", sc)
	}
}
