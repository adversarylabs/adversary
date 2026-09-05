package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	internaladversary "github.com/adversarylabs/adversary/internal/adversary"
	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/internal/githubreview"
	"github.com/adversarylabs/adversary/pkg/repository"
	"github.com/adversarylabs/adversary/pkg/review"
	"github.com/spf13/cobra"
)

func TestGitHubRunFailureExcludesSuccessFindingsAndCancellation(t *testing.T) {
	opts := &runOptions{githubReview: true}
	for _, err := range []error{nil, &internaladversary.FindingsError{Count: 1}, fmt.Errorf("wrapped: %w", context.Canceled)} {
		opts.recordGitHubRunFailure("review/code", "", err, "Error: ignored")
	}
	if len(opts.githubRunFailures) != 0 {
		t.Fatalf("not execution failures: %v", opts.githubRunFailures)
	}
	opts.githubReview = false
	opts.recordGitHubRunFailure("review/code", "", errors.New("failed"), "")
	if len(opts.githubRunFailures) != 0 {
		t.Fatal("collected diagnostics without GitHub review enabled")
	}
}

func TestGitHubRunFailureRedactsBeforeTruncationAndEscapesMarkup(t *testing.T) {
	t.Setenv("CAMEL_API_KEY", "secret-camel-token")
	t.Setenv("GITHUB_TOKEN", "secret-github-token")
	opts := &runOptions{githubReview: true}
	opts.recordGitHubRunFailure("review/<code>", "group-1", errors.New("child failed"),
		"warning\nModelReviewError: suspended <account> secret-github-token "+strings.Repeat("x", 425)+"secret-camel-token"+strings.Repeat("y", 600))
	got := opts.githubRunFailures[0]
	if strings.Contains(got, "secret-") || strings.Contains(got, "<account>") || strings.Contains(got, "review/<code>") {
		t.Fatalf("unsafe diagnostic: %s", got)
	}
	for _, want := range []string{"ModelReviewError: suspended", "&lt;account&gt;", "[redacted]", "group-1"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q: %s", want, got)
		}
	}
	if len(got) > 650 {
		t.Fatalf("unbounded diagnostic: %d bytes", len(got))
	}
}

func TestMaybeGitHubReviewPostsPartialStatusAndKeepsInlineFindings(t *testing.T) {
	t.Setenv("ADVERSARY_GITHUB_TOKEN", "test-token")
	for _, tc := range []struct {
		name                     string
		failed, finding, summary bool
	}{
		{"partial-inline-no-summary", true, true, false},
		{"failed-no-findings-no-summary", true, false, false},
		{"partial-with-summary", true, true, true},
		{"complete-inline-no-summary", false, true, false},
		{"complete-clean-no-summary", false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var addInput map[string]any
			submitted := false
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/files") {
					fmt.Fprint(w, `[{"filename":"a.go","patch":"@@ -1,1 +1,2 @@\n keep\n+added\n"}]`)
					return
				}
				var payload struct {
					Query     string         `json:"query"`
					Variables map[string]any `json:"variables"`
				}
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Error(err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				switch {
				case strings.Contains(payload.Query, "pullRequest(number"):
					fmt.Fprint(w, `{"data":{"repository":{"pullRequest":{"id":"PR_1","headRefOid":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}}`)
				case strings.Contains(payload.Query, "addPullRequestReview"):
					addInput, _ = payload.Variables["input"].(map[string]any)
					fmt.Fprint(w, `{"data":{"addPullRequestReview":{"pullRequestReview":{"id":"RV_1","state":"PENDING"}}}}`)
				case strings.Contains(payload.Query, "submitPullRequestReview"):
					submitted = true
					fmt.Fprint(w, `{"data":{"submitPullRequestReview":{"pullRequestReview":{"id":"RV_1","state":"COMMENTED"}}}}`)
				default:
					t.Errorf("unexpected query: %s", payload.Query)
					w.WriteHeader(http.StatusBadRequest)
				}
			}))
			defer srv.Close()
			opts := &runOptions{
				path: t.TempDir(), githubReview: true, githubRepo: "o/r", githubPR: 1,
				githubSubmit: true, githubIncludeSummary: tc.summary,
				githubAPIURL: srv.URL, githubRESTURL: srv.URL,
				modelProvider: "disabled-for-test",
			}
			if tc.failed {
				opts.recordGitHubRunFailure("review/code", "full-change", errors.New("child failed"), "ModelReviewError: Account is suspended")
			}
			var envs []githubreview.NamedEnvelope
			if tc.finding {
				line := 2
				envs = []githubreview.NamedEnvelope{{Adversary: "go/testing", Envelope: review.RunEnvelope{ProtocolVersion: 1, Result: review.ReviewResult{
					Adversary: review.ReviewAdversary{Name: "go/testing"},
					Findings:  []review.Finding{{ID: "f", Title: "Finding", Category: "correctness", Severity: "high", Confidence: "high", Summary: "A concrete issue", Evidence: []review.Evidence{{File: "a.go", Line: &line}}}},
				}}}}
			}
			if err := maybeGitHubReview(context.Background(), opts, envs, io.Discard); err != nil {
				t.Fatal(err)
			}
			body, _ := addInput["body"].(string)
			if tc.failed {
				for _, want := range []string{"Partial Adversary review", "did not complete", "review/code", "full-change", "Account is suspended"} {
					if !strings.Contains(body, want) {
						t.Fatalf("missing %q in %s", want, body)
					}
				}
			} else if strings.Contains(body, "Partial") || (!tc.summary && body != "") {
				t.Fatalf("unexpected body: %s", body)
			}
			threads, _ := addInput["threads"].([]any)
			if tc.finding {
				if len(threads) != 1 {
					t.Fatalf("inline finding lost: %#v", addInput)
				}
				thread := threads[0].(map[string]any)
				if thread["path"] != "a.go" || thread["line"] != float64(2) {
					t.Fatalf("wrong anchor: %#v", thread)
				}
			} else if len(threads) != 0 {
				t.Fatalf("unexpected threads: %#v", threads)
			}
			if submitted != (tc.failed || tc.finding) {
				t.Fatalf("submitted=%v", submitted)
			}
		})
	}
}

func TestRunFailuresRetainDiagnosticsAndExecutionExit(t *testing.T) {
	for _, mode := range []string{"single", "multi", "composed"} {
		t.Run(mode, func(t *testing.T) {
			var out, progress bytes.Buffer
			base := lifecycleTestApp(t, repository.Repository{Root: t.TempDir()}, &out, &progress)
			deps := base.Dependencies()
			failure := &internaladversary.ChildExitError{ExitCode: 1, Err: errors.New("child failed")}
			spy := &multiRecordingRuntime{inner: deps.Runtime,
				errs:         map[string]error{"broken": failure, "other": failure},
				stderrBodies: map[string]string{"broken": "ModelReviewError: Account is suspended\n", "other": "ModelReviewError: Account is suspended\n"},
			}
			deps.Runtime = spy
			app, err := application.New(deps)
			if err != nil {
				t.Fatal(err)
			}
			opts := &runOptions{githubReview: true, noCompose: true, noTelemetry: true, composeConcurrency: 1, format: "text"}
			refs := []string{"broken"}
			if mode != "single" {
				refs = append(refs, "other")
			}
			if mode == "composed" {
				err = runComposedAdversaries(context.Background(), app, opts, "broken", refs, "", "", &out, &progress)
			} else {
				err = runAdversaries(context.Background(), app, opts, refs, nil, nil, &out, &progress)
			}
			if !errors.Is(err, failure) || ExitCode(err) != 3 {
				t.Fatalf("lost execution error: %v, code=%d", err, ExitCode(err))
			}
			if len(opts.githubRunFailures) != len(refs) {
				t.Fatalf("missing failures: %v", opts.githubRunFailures)
			}
			for _, diagnostic := range opts.githubRunFailures {
				if !strings.Contains(diagnostic, "Account is suspended") {
					t.Fatalf("lost cause: %s", diagnostic)
				}
			}
			if mode == "single" && !strings.Contains(progress.String(), "Account is suspended") {
				t.Fatal("single-run live diagnostics were lost")
			}
		})
	}
}

type githubAutoFailureRuntime struct{ application.Runtime }

func (r githubAutoFailureRuntime) Auto(_ context.Context, opts application.AdversaryAutoOptions) (application.AdversaryAutoResult, error) {
	failure := &internaladversary.ChildExitError{ExitCode: 1, Err: errors.New("child failed")}
	for i, name := range []string{"first", "second"} {
		if err := opts.ReportRunStart(name, i+1, 2); err != nil {
			return application.AdversaryAutoResult{}, err
		}
		fmt.Fprintf(opts.Stderr, "ModelReviewError: %s failure\n", name)
		if err := opts.ReportRunFinish(name, i+1, 2, failure); err != nil {
			return application.AdversaryAutoResult{}, err
		}
	}
	return application.AdversaryAutoResult{}, &internaladversary.AutoExecutionError{Errors: []error{failure}}
}

func TestAutomaticRunFailureDiagnosticsAreScopedToEachJob(t *testing.T) {
	var out, progress bytes.Buffer
	base := lifecycleTestApp(t, repository.Repository{Root: t.TempDir()}, &out, &progress)
	deps := base.Dependencies()
	deps.Runtime = githubAutoFailureRuntime{deps.Runtime}
	app, err := application.New(deps)
	if err != nil {
		t.Fatal(err)
	}
	command := &cobra.Command{}
	command.SetContext(context.Background())
	opts := &runOptions{githubReview: true, noPull: true, noTelemetry: true, minimumConfidence: "medium"}
	err = runAutomaticSelection(command, app, opts, nil, nil, &out, &progress)
	if ExitCode(err) != 3 || len(opts.githubRunFailures) != 2 {
		t.Fatalf("err=%v, failures=%v", err, opts.githubRunFailures)
	}
	for i, name := range []string{"first", "second"} {
		if !strings.Contains(opts.githubRunFailures[i], "ModelReviewError: "+name+" failure") {
			t.Fatalf("wrong job diagnostic: %s", opts.githubRunFailures[i])
		}
	}
}
