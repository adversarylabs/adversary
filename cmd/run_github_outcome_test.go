package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/internal/githubreview"
	"github.com/adversarylabs/adversary/pkg/outcomecontext"
	"github.com/adversarylabs/adversary/pkg/repository"
)

type outcomeIntentRuntimeStub struct {
	application.Runtime
	provider application.ModelReviewProvider
}

func (s *outcomeIntentRuntimeStub) ModelReviewProvider(application.ModelReviewConfig) (application.ModelReviewProvider, error) {
	return s.provider, nil
}

type outcomeIntentProviderStub struct {
	err error
}

func (s outcomeIntentProviderStub) Name() string  { return "stub" }
func (s outcomeIntentProviderStub) Model() string { return "stub" }
func (s outcomeIntentProviderStub) Review(context.Context, application.ModelReviewRequest) (json.RawMessage, error) {
	return nil, s.err
}

func TestDetectOutcomeIntentPreservesTerminationErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{name: "cancellation", err: context.Canceled},
		{name: "deadline", err: context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			base := lifecycleTestApp(t, repository.Repository{Root: t.TempDir()}, &stdout, &stderr)
			deps := base.Dependencies()
			deps.Runtime = &outcomeIntentRuntimeStub{
				Runtime:  deps.Runtime,
				provider: outcomeIntentProviderStub{err: tc.err},
			}
			app, err := application.New(deps)
			if err != nil {
				t.Fatal(err)
			}
			opts := &runOptions{outcomeContext: outcomecontext.GitHubPullRequest("acme/app", 42, "Ship it", "")}
			err = detectOutcomeIntent(context.Background(), app, opts, io.Discard)
			if !errors.Is(err, tc.err) {
				t.Fatalf("error = %v, want %v", err, tc.err)
			}
		})
	}
}

func TestDetectOutcomeIntentKeepsOrdinaryInferenceFailureNonfatal(t *testing.T) {
	var stdout, stderr bytes.Buffer
	base := lifecycleTestApp(t, repository.Repository{Root: t.TempDir()}, &stdout, &stderr)
	deps := base.Dependencies()
	deps.Runtime = &outcomeIntentRuntimeStub{
		Runtime:  deps.Runtime,
		provider: outcomeIntentProviderStub{err: errors.New("provider unavailable")},
	}
	app, err := application.New(deps)
	if err != nil {
		t.Fatal(err)
	}
	opts := &runOptions{outcomeContext: outcomecontext.GitHubPullRequest("acme/app", 42, "Ship it", "")}
	if err := detectOutcomeIntent(context.Background(), app, opts, io.Discard); err != nil {
		t.Fatalf("ordinary inference failure became fatal: %v", err)
	}
}

func TestMaybeGitHubReviewSummarySettingControlsOutcomeBasis(t *testing.T) {
	for _, tc := range []struct {
		name           string
		includeSummary bool
		wantBasis      bool
	}{
		{name: "included", includeSummary: true, wantBasis: true},
		{name: "omitted", includeSummary: false, wantBasis: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, name := range []string{"ADVERSARY_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"} {
				t.Setenv(name, "")
			}
			planPath := filepath.Join(t.TempDir(), "plan.json")
			opts := &runOptions{
				path:                 t.TempDir(),
				githubReview:         true,
				githubDryRun:         true,
				githubPlanFile:       planPath,
				githubRepo:           "acme/app",
				githubPR:             42,
				githubIncludeSummary: tc.includeSummary,
				modelProvider:        "disabled-for-test",
				outcomeContext:       outcomecontext.GitHubPullRequest("acme/app", 42, "Permit repository-scoped pulls", ""),
			}
			if err := maybeGitHubReview(context.Background(), nil, opts, nil, "", "", io.Discard); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(planPath)
			if err != nil {
				t.Fatal(err)
			}
			var plan githubreview.CommentPlan
			if err := json.Unmarshal(raw, &plan); err != nil {
				t.Fatal(err)
			}
			if got := plan.ReviewBasis != ""; got != tc.wantBasis {
				t.Fatalf("review basis = %q", plan.ReviewBasis)
			}
		})
	}
}
