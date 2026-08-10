package collect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adversarylabs/adversary/internal/train/scope"
)

func TestBuildCasesFromCacheFiltered(t *testing.T) {
	dir := t.TempDir()
	// Minimal GitHub API shapes.
	pull := `{
	  "number": 42,
	  "title": "fix race",
	  "html_url": "https://github.com/acme/r/pull/42",
	  "base": {"sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "ref": "main"},
	  "head": {"sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "ref": "feat"},
	  "user": {"login": "author1"},
	  "merged_at": "2024-01-02T00:00:00Z"
	}`
	reviews := `[
	  {"id": 1, "user": {"login": "mitchellh"}, "body": "This goroutine can leak after Shutdown if the context is not cancelled properly.", "state": "CHANGES_REQUESTED", "commit_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "submitted_at": "2024-01-02T01:00:00Z"}
	]`
	comments := `[
	  {"id": 2, "pull_request_review_id": 1, "user": {"login": "mitchellh"}, "body": "Also a data race on the shared map without synchronization.", "path": "worker.go", "line": 10, "commit_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "created_at": "2024-01-02T01:01:00Z"},
	  {"id": 3, "pull_request_review_id": 1, "in_reply_to_id": 2, "user": {"login": "author1"}, "body": "For context, this is because we already serialize access in the caller.", "path": "worker.go", "line": 10, "commit_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "created_at": "2024-01-02T01:02:00Z"},
	  {"id": 4, "pull_request_review_id": 1, "in_reply_to_id": 2, "user": {"login": "mitchellh"}, "body": "Please add an assertion that proves the caller keeps this map serialized.", "path": "worker.go", "line": 10, "commit_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "created_at": "2024-01-02T01:03:00Z"},
	  {"id": 5, "pull_request_review_id": 1, "user": {"login": "mitchellh"}, "body": "<!-- Thoughts represent an idea that popped up from reviewing. These comments are non-blocking by nature. --> Data race: this shared map is written without synchronization; guard it with the existing mutex.", "path": "worker.go", "line": 12, "commit_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "created_at": "2024-01-02T01:04:00Z"}
	]`
	_ = os.WriteFile(filepath.Join(dir, "pull.json"), []byte(pull), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "reviews.json"), []byte(reviews), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "review-comments.json"), []byte(comments), 0o600)

	router := &scope.Router{
		Candidates: []scope.Candidate{
			{ID: "go-concurrency", AdversaryName: "go-concurrency", Mission: "Go concurrency races lifecycle goroutine"},
		},
		UseLLM: false,
	}
	cases, err := BuildCasesFromCacheFiltered("acme", "r", 42, dir, nil, router, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) == 0 {
		t.Fatal("expected cases")
	}
	foundExplanation, foundRequest, foundNormalized := false, false, false
	for _, label := range cases[0].Labels.ExpectedConcerns {
		switch {
		case strings.Contains(label.Summary, "For context"):
			foundExplanation = true
			if label.Approved || label.Scope != string(scope.OutOfScope) || label.ScopeMethod != "thread-metadata" {
				t.Errorf("author reply should not be gold: %+v", label)
			}
		case strings.Contains(label.Summary, "Please add"):
			foundRequest = true
			if !label.Approved || label.Scope != string(scope.InScope) {
				t.Errorf("explicit reviewer request should remain gold: %+v", label)
			}
		case strings.Contains(label.Summary, "Data race"):
			foundNormalized = true
			if strings.Contains(label.Summary, "Thoughts represent") || !label.Approved {
				t.Errorf("review guidance should be removed before persisting gold: %+v", label)
			}
		}
	}
	if !foundExplanation || !foundRequest || !foundNormalized {
		t.Fatalf("missing metadata regression labels: explanation=%v request=%v normalized=%v", foundExplanation, foundRequest, foundNormalized)
	}
	// authors_only filter
	cases2, err := BuildCasesFromCacheFiltered("acme", "r", 42, dir, nil, router, func(login string) bool {
		return login == "nobody"
	})
	if err != nil {
		t.Fatal(err)
	}
	// may still have structure but no gold
	_ = cases2
}

func TestBlockedFromErrRateLimit(t *testing.T) {
	bl := blockedFromErr("github-api", "collect", &RateLimitError{Message: "API rate limit exceeded"})
	if bl.Classification != "rate-limit" {
		t.Fatalf("%+v", bl)
	}
	bl2 := blockedFromErr("github-api", "collect", errString("401 bad"))
	if bl2.Classification != "auth" {
		t.Fatalf("%+v", bl2)
	}
}

type errString string

func (e errString) Error() string { return string(e) }
