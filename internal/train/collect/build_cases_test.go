package collect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adversarylabs/adversary/internal/train/cases"
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
	  "merged_at": "2024-01-03T00:00:00Z"
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

func TestBuildCasesRejectsInlineChildrenOfAutomatedParentReview(t *testing.T) {
	dir := t.TempDir()
	pull := `{
  "number": 9278,
  "title": "fix stale query state",
  "html_url": "https://github.com/acme/r/pull/9278",
  "base": {"sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
  "head": {"sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
  "user": {"login": "author1"}
}`
	reviews := `[
  {"id": 101, "user": {"login": "human-maintainer"}, "body": "The fix is sound. One concern inline.\n\n<!-- hermes-pr-review bbbbbbb -->", "state": "COMMENTED", "commit_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "submitted_at": "2024-01-02T01:00:00Z"}
]`
	comments := `[
  {"id": 102, "pull_request_review_id": 101, "user": {"login": "human-maintainer"}, "body": "This search path leaves the applied filter state stale, so the next page queries with the wrong filters.", "path": "SearchPage.tsx", "line": 145, "commit_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "created_at": "2024-01-02T01:01:00Z"}
]`
	for name, body := range map[string]string{
		"pull.json": pull, "reviews.json": reviews, "review-comments.json": comments,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	router := &scope.Router{
		Candidates: []scope.Candidate{{ID: "typescript", AdversaryName: "typescript", Mission: "TypeScript and React state correctness"}},
		UseLLM:     false,
	}
	got, err := BuildCasesFromCacheFiltered("acme", "r", 9278, dir, nil, router, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("cases = %d, want one automated review evidence case", len(got))
	}
	foundInline := false
	for _, label := range got[0].Labels.ExpectedConcerns {
		if !strings.HasPrefix(label.ID, "c-102-") {
			continue
		}
		foundInline = true
		if label.Approved || label.Scope != string(scope.OutOfScope) || label.OwnerAdversary != "" {
			t.Fatalf("automated child became gold: %+v", label)
		}
		if label.ScopeMethod != "thread-metadata" || !strings.Contains(label.ScopeReason, "automated parent review") {
			t.Fatalf("automated provenance was not retained: %+v", label)
		}
	}
	if !foundInline {
		t.Fatal("expected inline child label to remain as rejected evidence")
	}
}

func TestBuildCasesPrefersLatestInScopeReview(t *testing.T) {
	dir := t.TempDir()
	pull := `{
	  "number": 42,
	  "title": "fix races",
	  "html_url": "https://github.com/acme/r/pull/42",
	  "base": {"sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	  "head": {"sha": "cccccccccccccccccccccccccccccccccccccccc"},
	  "user": {"login": "author1"}
	}`
	reviews := `[
	  {"id": 1, "user": {"login": "old-reviewer"}, "body": "", "state": "CHANGES_REQUESTED", "commit_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "submitted_at": "2024-01-02T01:00:00Z"},
	  {"id": 2, "user": {"login": "new-reviewer"}, "body": "", "state": "CHANGES_REQUESTED", "commit_id": "cccccccccccccccccccccccccccccccccccccccc", "submitted_at": "2024-01-03T01:00:00Z"},
	  {"id": 3, "user": {"login": "maintainer-contributor"}, "body": "", "state": "COMMENTED", "commit_id": "cccccccccccccccccccccccccccccccccccccccc", "submitted_at": "2024-01-04T01:00:00Z"}
	]`
	comments := `[
	  {"id": 11, "pull_request_review_id": 1, "user": {"login": "old-reviewer"}, "body": "This goroutine can leak after shutdown.", "path": "worker.go", "line": 10, "commit_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "created_at": "2024-01-02T01:01:00Z"},
	  {"id": 12, "pull_request_review_id": 2, "user": {"login": "new-reviewer"}, "body": "This goroutine can leak after Shutdown if the context is not cancelled; this is the newest reviewer concern.", "path": "worker.go", "line": 20, "commit_id": "cccccccccccccccccccccccccccccccccccccccc", "created_at": "2024-01-03T01:01:00Z"},
	  {"id": 13, "pull_request_review_id": 3, "in_reply_to_id": 12, "user": {"login": "maintainer-contributor"}, "body": "You're right. I pushed a fix that cancels the context and added regression tests.", "path": "worker.go", "line": 20, "commit_id": "cccccccccccccccccccccccccccccccccccccccc", "created_at": "2024-01-04T01:01:00Z"}
	]`
	for name, body := range map[string]string{
		"pull.json": pull, "reviews.json": reviews, "review-comments.json": comments,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	router := &scope.Router{
		Candidates: []scope.Candidate{{ID: "go-concurrency", AdversaryName: "go-concurrency", Mission: "Go concurrency races lifecycle goroutine"}},
		UseLLM:     false,
	}
	got, err := BuildCasesFromCacheFiltered("acme", "r", 42, dir, nil, router, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("expected at least one case")
	}
	var selected *cases.Case
	for _, candidate := range got {
		for _, label := range candidate.Labels.ExpectedConcerns {
			if label.Approved {
				selected = candidate
				break
			}
		}
		if selected != nil {
			break
		}
	}
	if selected == nil {
		t.Fatal("expected an approved reviewer concern")
	}
	if len(selected.ReviewEvent.Reviewers) != 1 || selected.ReviewEvent.Reviewers[0] != "new-reviewer" {
		t.Fatalf("selected reviewers = %#v, want newest reviewer concern", selected.ReviewEvent.Reviewers)
	}
	if len(selected.Comments) != 1 || !strings.Contains(selected.Comments[0].Body, "newest reviewer concern") {
		t.Fatalf("selected comments = %#v, want newest reviewer comment", selected.Comments)
	}
}

func TestBuildCasesIgnoresPostMergeReviewComments(t *testing.T) {
	dir := t.TempDir()
	pull := `{
  "number": 938,
  "title": "fix response lifecycle",
  "html_url": "https://github.com/acme/r/pull/938",
  "base": {"sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
  "head": {"sha": "cccccccccccccccccccccccccccccccccccccccc"},
  "user": {"login": "author1"},
  "merged_at": "2024-01-03T12:00:00Z"
}`
	reviews := `[
  {"id": 1, "user": {"login": "reviewer"}, "body": "", "state": "CHANGES_REQUESTED", "commit_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "submitted_at": "2024-01-02T10:00:00Z"},
  {"id": 2, "user": {"login": "reviewer"}, "body": "", "state": "COMMENTED", "commit_id": "cccccccccccccccccccccccccccccccccccccccc", "submitted_at": "2024-01-03T16:00:00Z"}
]`
	comments := `[
  {"id": 11, "pull_request_review_id": 1, "user": {"login": "reviewer"}, "body": "This goroutine leaks unless its context is cancelled.", "path": "worker.go", "line": 10, "commit_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "created_at": "2024-01-02T10:01:00Z"},
  {"id": 12, "pull_request_review_id": 2, "user": {"login": "reviewer"}, "body": "Maybe publish only one of the response or error values.", "path": "worker.go", "line": 20, "commit_id": "cccccccccccccccccccccccccccccccccccccccc", "created_at": "2024-01-03T16:01:00Z"}
]`
	for name, body := range map[string]string{
		"pull.json": pull, "reviews.json": reviews, "review-comments.json": comments,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	router := &scope.Router{
		Candidates: []scope.Candidate{{ID: "go-concurrency", AdversaryName: "go-concurrency", Mission: "Go concurrency goroutine lifecycle response handoff"}},
		UseLLM:     false,
	}
	got, err := BuildCasesFromCacheFiltered("acme", "r", 938, dir, nil, router, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 || len(got[0].Comments) != 1 {
		t.Fatalf("cases = %#v, want only the pre-merge review", got)
	}
	if got[0].Comments[0].ID != 11 || strings.Contains(got[0].Comments[0].Body, "publish only one") {
		t.Fatalf("post-merge suggestion leaked into gold: %#v", got[0].Comments)
	}
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
