package judge

import (
	"testing"

	"github.com/adversarylabs/adversary/internal/train/cases"
	"github.com/adversarylabs/adversary/internal/train/normalize"
)

func TestUnsupportedClaimRateNotDoubleCounted(t *testing.T) {
	// Plausible engineering claim (keyword "error") with empty evidence and no gold match.
	// Previously unsupported was incremented twice → rate 2.0.
	review := &normalize.Review{
		ReviewerID: "engineering-review",
		Findings: []normalize.Finding{
			{
				ID:       "only",
				Severity: "high",
				Claim:    "there is an error in the error handling path that needs review",
				Evidence: "",
				File:     "",
			},
		},
	}
	j := JudgeReview(review, nil)
	if j.UnsupportedClaimRate != 1.0 {
		t.Fatalf("UnsupportedClaimRate=%v want 1.0 (must not double-count)", j.UnsupportedClaimRate)
	}
	if j.FalsePositiveCount != 1 {
		t.Fatalf("FalsePositiveCount=%d want 1", j.FalsePositiveCount)
	}
}

func TestJudgeReviewMatchesExpectedConcern(t *testing.T) {
	review := &normalize.Review{
		ReviewerID: "engineering-review",
		Findings: []normalize.Finding{
			{
				ID:       "f1",
				File:     "sdk/trace/span_processor.go",
				Severity: "high",
				Claim:    "worker goroutine lifecycle not tied to shutdown cancellation may leak",
				Evidence: "go p.worker()",
			},
			{
				ID:       "f2",
				Severity: "info",
				Claim:    "maybe wrong",
			},
		},
	}
	expected := []cases.ExpectedConcern{
		{
			ID:         "c-leak-1",
			Summary:    "Worker goroutine lifecycle not tied to Shutdown/cancellation; risk of leak after stop",
			Importance: "high",
			File:       "sdk/trace/span_processor.go",
			Approved:   true,
		},
		{
			ID:         "c-err-1",
			Summary:    "Export errors ignored during shutdown path",
			Importance: "high",
			Approved:   true,
		},
	}
	j := JudgeReview(review, expected)
	if len(j.ExpectedMatched) < 1 {
		t.Fatalf("expected at least one match: matched=%v missed=%v findings=%+v", j.ExpectedMatched, j.ExpectedMissed, j.Findings)
	}
	if j.ImportantRecall <= 0 {
		t.Fatalf("recall=%v", j.ImportantRecall)
	}
	fails := ExtractFailures("case-1", j)
	if len(fails) < 1 {
		t.Fatal("expected failures for missed concern and/or weak finding")
	}
}
