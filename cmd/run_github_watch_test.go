package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/doomerlabs/adversary/internal/githubreview"
	"github.com/doomerlabs/adversary/pkg/adversarylabs"
	"github.com/doomerlabs/adversary/pkg/repository"
	"github.com/doomerlabs/adversary/pkg/review"
)

func TestGitHubReviewWatchSameHeadRerun(t *testing.T) {
	t.Setenv("ADVERSARY_GITHUB_TOKEN", "github-secret")
	const head = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const requestID = "b67c9d88-8b52-40f9-a49a-8f8fbaf16a9a"
	for _, registrationFails := range []bool{false, true} {
		t.Run(fmt.Sprintf("registrationFails=%v", registrationFails), func(t *testing.T) {
			created, submitted := 0, 0
			var watches []adversarylabs.ReviewWatch
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/reviews/watches" {
					if created != submitted || submitted != len(watches)+1 {
						t.Error("watch registration must follow successful publication exactly once")
					}
					if r.Header.Get("Authorization") != "Bearer ci-secret" {
						t.Error("missing scoped CI authentication")
					}
					var watch adversarylabs.ReviewWatch
					if err := json.NewDecoder(r.Body).Decode(&watch); err != nil {
						t.Error(err)
					}
					watches = append(watches, watch)
					if registrationFails {
						w.Header().Set("X-Request-ID", requestID)
						w.WriteHeader(http.StatusBadRequest)
						fmt.Fprint(w, `{"error":"invalid_request","code":"duplicate_finding","field":"comments[1].finding_id","message":"Bearer ci-secret github-secret"}`)
					} else {
						w.WriteHeader(http.StatusCreated)
					}
					return
				}
				if strings.HasSuffix(r.URL.Path, "/files") {
					fmt.Fprint(w, `[{"filename":".depot/workflows/pr.yml","patch":"@@ -1,1 +1,2 @@\n keep\n+added\n"}]`)
					return
				}
				var payload struct{ Query string }
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Error(err)
				}
				switch {
				case strings.Contains(payload.Query, "pullRequest(number"):
					fmt.Fprintf(w, `{"data":{"repository":{"pullRequest":{"id":"PR_1","headRefOid":%q}}}}`, head)
				case strings.Contains(payload.Query, "addPullRequestReview"):
					created++
					fmt.Fprintf(w, `{"data":{"addPullRequestReview":{"pullRequestReview":{"id":"RV_%d","state":"PENDING"}}}}`, created)
				case strings.Contains(payload.Query, "submitPullRequestReview"):
					submitted++
					fmt.Fprintf(w, `{"data":{"submitPullRequestReview":{"pullRequestReview":{"id":"RV_%d","state":"COMMENTED","url":"https://github.com/acme/platform/pull/185#pullrequestreview-%d"}}}}`, created, created)
				default:
					t.Errorf("unexpected GitHub request: %s", payload.Query)
					w.WriteHeader(http.StatusBadRequest)
				}
			}))
			defer srv.Close()
			var output, progress bytes.Buffer
			app := lifecycleTestApp(t, repository.Repository{Root: t.TempDir()}, &output, &progress)
			if err := app.Dependencies().Auth.SetAuth(adversarylabs.AuthKey(srv.URL, "default"), adversarylabs.Auth{Token: "ci-secret"}); err != nil {
				t.Fatal(err)
			}
			line := 2
			var envelopes []githubreview.NamedEnvelope
			for _, name := range []string{"engineering-policy", "access-policy"} {
				envelopes = append(envelopes, githubreview.NamedEnvelope{
					Adversary: "acme/" + name + ":0.0.2",
					Envelope: review.RunEnvelope{ProtocolVersion: 1, Result: review.ReviewResult{
						Adversary: review.ReviewAdversary{Name: "private/" + name, Version: "0.0.2"},
						Findings:  []review.Finding{{ID: "finding-shared", RuleID: "private-policy", Title: "Finding", Severity: "high", Summary: "A concrete issue", Evidence: []review.Evidence{{File: ".depot/workflows/pr.yml", Line: &line}}}},
					}},
				})
			}
			for run := 1; run <= 2; run++ {
				opts := &runOptions{
					path: t.TempDir(), githubReview: true, githubRepo: "acme/platform", githubPR: 185,
					githubSubmit: true, githubAPIURL: srv.URL, githubRESTURL: srv.URL,
					modelProvider:   "disabled-for-test",
					resolvedHeadSHA: head,
				}
				if err := maybeGitHubReview(context.Background(), app, opts, envelopes, srv.URL, "default", &progress); err != nil {
					t.Fatalf("published review became a failure: %v", err)
				}
				if len(opts.githubRunFailures) != 0 || created != run || submitted != run || len(watches) != run {
					t.Fatalf("registration caused a package failure or duplicate publication: created=%d submitted=%d watches=%d failures=%v", created, submitted, len(watches), opts.githubRunFailures)
				}
				watch := watches[run-1]
				if watch.ReviewNodeID != fmt.Sprintf("RV_%d", run) || watch.HeadSHA != head || len(watch.Comments) != 2 || watch.Repository != "acme/platform" || watch.PullRequest != 185 {
					t.Fatalf("wrong review registered: %#v", watch)
				}
				for i, comment := range watch.Comments {
					if comment.FindingID != "finding-shared" || comment.PackageName != envelopes[i].Envelope.Result.Adversary.Name || !strings.Contains(comment.Body, "head="+head) {
						t.Fatalf("lost package-scoped finding provenance: %#v", comment)
					}
				}
			}
			log := progress.String()
			if registrationFails {
				for _, want := range []string{"Warning: review posted but feedback watch registration failed", "comments[1].finding_id", requestID} {
					if !strings.Contains(log, want) {
						t.Errorf("missing diagnostic %q in %s", want, log)
					}
				}
			} else if strings.Count(log, "Feedback watch registered for 2 review comment(s).") != 2 {
				t.Errorf("missing registration successes: %s", log)
			}
			if strings.Contains(log, "ci-secret") || strings.Contains(log, "github-secret") {
				t.Fatal("credentials leaked into diagnostics")
			}
		})
	}
}
