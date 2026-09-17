package cmd

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	internaladversary "github.com/adversarylabs/adversary/internal/adversary"
	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/internal/telemetry"
	"github.com/adversarylabs/adversary/pkg/adversarylabs"
	"github.com/adversarylabs/adversary/pkg/repository"
	"github.com/adversarylabs/adversary/pkg/review"
)

type sourceIdentityRuntime struct{ application.Runtime }

func (sourceIdentityRuntime) RunSourceIdentity(context.Context, string) (application.RunSourceIdentity, error) {
	return application.RunSourceIdentity{Ref: "feature/run-targets", SHA: strings.Repeat("a", 40)}, nil
}

func TestWithRunSourceContextReportsPRBranchAndCommit(t *testing.T) {
	var out, errOut bytes.Buffer
	app := lifecycleTestApp(t, repository.Repository{Root: t.TempDir()}, &out, &errOut)
	deps := app.Dependencies()
	deps.Runtime = sourceIdentityRuntime{Runtime: deps.Runtime}
	app, err := application.New(deps)
	if err != nil {
		t.Fatal(err)
	}
	got := withRunSourceContext(context.Background(), app, adversarylabs.RunUsageReport{}, &runOptions{
		path: t.TempDir(), githubPR: 213,
	})
	if got.PullRequest != 213 || got.GitRef != "feature/run-targets" || !fullGitSHA.MatchString(got.GitSHA) {
		t.Fatalf("source context = %#v", got)
	}
}

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
	got.StartedAtUnixNano = ""
	got.EndedAtUnixNano = ""
	if got != want {
		t.Fatalf("result = %#v, want %#v", got, want)
	}
}

func TestRunUsageResultReflectsFailure(t *testing.T) {
	if got := runUsageResult("go/security", errors.New("boom"), time.Second, nil).Status; got != "failed" {
		t.Fatalf("failed status = %q", got)
	}
}

func TestRunUsageResultDistinguishesSkippedInvocation(t *testing.T) {
	envelope := review.RunEnvelope{Result: review.ReviewResult{
		Observations: []review.Note{{Key: "run-skipped", Summary: "No changed files matched."}},
	}}

	got := runUsageResult("go/security", nil, time.Second, &envelope)
	if got.Status != "skipped" {
		t.Fatalf("status = %q, want skipped", got.Status)
	}
}
