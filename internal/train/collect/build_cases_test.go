package collect

import (
	"os"
	"path/filepath"
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
	  {"id": 2, "user": {"login": "mitchellh"}, "body": "Also a data race on the shared map without synchronization.", "path": "worker.go", "line": 10, "commit_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "created_at": "2024-01-02T01:01:00Z"}
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
