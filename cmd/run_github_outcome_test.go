package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"github.com/adversarylabs/adversary/internal/application"
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
