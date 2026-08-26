package cmd

import (
	"errors"
	"testing"
	"time"

	internaladversary "github.com/adversarylabs/adversary/internal/adversary"
	"github.com/adversarylabs/adversary/internal/telemetry"
	"github.com/adversarylabs/adversary/pkg/adversarylabs"
	"github.com/adversarylabs/adversary/pkg/review"
)

func TestSanitizeAdversarySelectionDelegates(t *testing.T) {
	got := telemetry.SanitizeAdversarySelection([]string{
		"registry.adversarylabs.ai/ci/gitlab-ci:0.0.4",
		"./x",
	})
	if len(got) != 2 || got[0] != "ci/gitlab-ci" || got[1] != "local" {
		t.Fatalf("got %#v", got)
	}
}

func TestRunUsageResultContainsOnlyAggregateSeverities(t *testing.T) {
	envelope := review.RunEnvelope{Result: review.ReviewResult{
		Timing: &review.Timing{TotalMS: 321},
		Findings: []review.Finding{
			{Title: "private title", Summary: "private body", Severity: "critical"},
			{Title: "another title", Evidence: []review.Evidence{{File: "secret.go"}}, Severity: "high"},
			{Severity: "medium"},
		},
	}}

	got := runUsageResult(
		"go/security",
		&internaladversary.FindingsError{Count: 3},
		5*time.Second,
		&envelope,
	)

	want := adversarylabs.RunUsageAdversaryResult{
		Adversary:     "go/security",
		Status:        "findings",
		DurationMS:    321,
		CriticalCount: 1,
		HighCount:     1,
		MediumCount:   1,
	}
	if got != want {
		t.Fatalf("result = %#v, want %#v", got, want)
	}
}

func TestRunUsageResultReflectsFailure(t *testing.T) {
	if got := runUsageResult("go/security", errors.New("boom"), time.Second, nil).Status; got != "failed" {
		t.Fatalf("failed status = %q", got)
	}
}
