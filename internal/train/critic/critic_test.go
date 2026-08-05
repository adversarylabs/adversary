package critic

import (
	"strings"
	"testing"

	"github.com/adversarylabs/adversary/internal/train/judge"
)

func TestAnalyzeFailuresGeneralized(t *testing.T) {
	failures := []judge.Failure{
		{CaseID: "c1", Kind: "missed-concern", Detail: "missed leak", ConcernID: "a"},
		{CaseID: "c1", Kind: "missed-concern", Detail: "missed err", ConcernID: "b"},
		{CaseID: "c2", Kind: "false-positive", Detail: "noise", FindingID: "f1"},
		{CaseID: "c2", Kind: "unsupported-claim", Detail: "no evidence", FindingID: "f2"},
		{CaseID: "c3", Kind: "missed-concern", Detail: "missed race", ConcernID: "c"},
	}
	hyps := AnalyzeFailures(failures, "engineering-review")
	if len(hyps) < 2 {
		t.Fatalf("expected multiple hypotheses, got %d", len(hyps))
	}
	for _, h := range hyps {
		if h.GeneralizedFailureMode == "" || h.WhyNotRepoSpecific == "" {
			t.Fatalf("incomplete hypothesis: %+v", h)
		}
		if strings.Contains(strings.ToLower(h.Principle), "opentelemetry") {
			t.Fatalf("repo-specific principle: %s", h.Principle)
		}
		if h.OwningAdversary != "engineering-review" {
			t.Fatalf("owner=%s", h.OwningAdversary)
		}
	}
}
