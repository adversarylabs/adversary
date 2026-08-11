package collect

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/adversarylabs/adversary/internal/githubapi"
	"github.com/adversarylabs/adversary/internal/train/dataroot"
	"github.com/adversarylabs/adversary/internal/train/scope"
)

func TestCollectPRReplaysCompleteCacheOnRateLimit(t *testing.T) {
	githubapi.ResetRateGateForTest()
	t.Cleanup(githubapi.ResetRateGateForTest)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"API rate limit exceeded"}`))
	}))
	defer server.Close()

	root := t.TempDir()
	cacheDir := filepath.Join(root, "github-cache", "acme", "r", "pr-42")
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(cacheDir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("pull.json", `{
	  "number": 42,
	  "title": "fix race",
	  "html_url": "https://github.com/acme/r/pull/42",
	  "base": {"sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	  "head": {"sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
	  "user": {"login": "author1"}
	}`)
	write("reviews.json", `[
	  {"id": 1, "user": {"login": "reviewer"}, "body": "", "state": "CHANGES_REQUESTED", "commit_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "submitted_at": "2024-01-02T01:00:00Z"}
	]`)
	write("review-comments.json", `[
	  {"id": 2, "pull_request_review_id": 1, "user": {"login": "reviewer"}, "body": "This shared map is written concurrently without synchronization.", "path": "worker.go", "line": 10, "commit_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "created_at": "2024-01-02T01:01:00Z"}
	]`)

	client := githubapi.NewClient("token")
	client.HTTP = server.Client()
	client.RESTBase = server.URL
	router := &scope.Router{
		Candidates: []scope.Candidate{{ID: "go-concurrency", AdversaryName: "go-concurrency", Mission: "Go concurrency races and shared state"}},
		UseLLM:     false,
	}
	result, err := CollectPRWithOptions(root, "acme", "r", 42, CollectOptions{Client: client, Router: router})
	if err != nil {
		t.Fatal(err)
	}
	if result.Blocked != nil {
		t.Fatalf("expected cache replay, got blocked: %+v", result.Blocked)
	}
	if !result.CacheReused || result.ExecutionClass != dataroot.ClassReplayed {
		t.Fatalf("unexpected replay result: %+v", result)
	}
	if len(result.CaseCandidates) == 0 {
		t.Fatal("expected cached review case")
	}
}

func TestCollectPRDoesNotReplayCacheOnAuthFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"Bad credentials"}`))
	}))
	defer server.Close()

	client := githubapi.NewClient("bad-token")
	client.HTTP = server.Client()
	client.RESTBase = server.URL
	result, err := CollectPRWithOptions(t.TempDir(), "acme", "r", 42, CollectOptions{Client: client})
	if err != nil {
		t.Fatal(err)
	}
	if result.Blocked == nil || result.Blocked.Classification != "auth" || result.CacheReused {
		t.Fatalf("expected auth block without replay: %+v", result)
	}
}
