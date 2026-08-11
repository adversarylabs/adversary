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
	foundExplanation, foundRequest, foundNormalized, foundRootContext := false, false, false, false
	for _, label := range cases[0].Labels.ExpectedConcerns {
		switch {
		case strings.HasPrefix(label.ID, "c-2-"):
			foundRootContext = true
			if len(label.ThreadContext) != 2 {
				t.Fatalf("root thread context = %#v, want author and reviewer replies", label.ThreadContext)
			}
			if label.ThreadContext[0].Role != "pull_request_author" || !strings.Contains(label.ThreadContext[0].Body, "serialize access") {
				t.Fatalf("author explanation was not explicitly labeled context: %#v", label.ThreadContext)
			}
			if label.ThreadContext[1].Role != "reviewer" || !strings.Contains(label.ThreadContext[1].Body, "add an assertion") {
				t.Fatalf("reviewer follow-up was not retained as context: %#v", label.ThreadContext)
			}
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
	if !foundExplanation || !foundRequest || !foundNormalized || !foundRootContext {
		t.Fatalf("missing metadata regression labels: explanation=%v request=%v normalized=%v root-context=%v", foundExplanation, foundRequest, foundNormalized, foundRootContext)
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

func TestBuildCasesRejectsSingleInlineConcernDeferredByReviewSummary(t *testing.T) {
	dir := t.TempDir()
	pull := `{
  "number": 4317,
  "title": "make pre-existing privileged test path dynamic",
  "html_url": "https://github.com/project-zot/zot/pull/4317",
  "base": {"sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
  "head": {"sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
  "user": {"login": "pull-author"}
}`
	reviews := `[{
  "id": 4908126748,
  "user": {"login": "reviewer"},
  "body": "LGTM. One comment unrelated to the scope of the PR, but might be a good one to take in the next PR.",
  "state": "APPROVED",
  "commit_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "submitted_at": "2026-08-11T16:08:51Z"
}]`
	comments := `[{
  "id": 3759513262,
  "pull_request_review_id": 4908126748,
  "user": {"login": "reviewer"},
  "body": "This is an existing path, but modifying /etc/ paths seems risky IMO. Is there any chance this could also be a temp path with the same permissions as /etc/ so that it can be simulated instead?",
  "path": "pkg/cli/client/elevated_test.go",
  "line": 92,
  "commit_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "created_at": "2026-08-11T15:50:21Z",
  "diff_hunk": "@@ -88,7 +92,7 @@\\n- privilegedCertsDir := \"/etc/containers/certs.d/localhost:8089\"\\n+ privilegedCertsDir := filepath.Join(\"/etc/containers/certs.d\", dynamicPort)\\n- defer exec.Command(\"rm\", \"-rf\", privilegedCertsDir)\\n+ defer func() { _ = exec.Command(\"rm\", \"-rf\", privilegedCertsDir).Run() }()"
}]`
	for name, body := range map[string]string{
		"pull.json": pull, "reviews.json": reviews, "review-comments.json": comments,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	router := &scope.Router{Candidates: []scope.Candidate{{
		ID: "person-maintainer", AdversaryName: "person-maintainer",
		Mission: "Everything is in scope. Do not exclude nits.",
	}}}
	got, err := BuildCasesFromCacheFiltered("project-zot", "zot", 4317, dir, nil, router, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("cases = %d, want one", len(got))
	}
	found := false
	for _, label := range got[0].Labels.ExpectedConcerns {
		if !strings.HasPrefix(label.ID, "c-3759513262-") {
			continue
		}
		found = true
		if label.Approved || label.OwnerAdversary != "" || label.Scope != string(scope.OutOfScope) {
			t.Fatalf("explicitly deferred inline concern became gold: %+v", label)
		}
		if label.ScopeMethod != "review-metadata" || !strings.Contains(label.ScopeReason, "outside the current PR") {
			t.Fatalf("review disposition provenance was lost: %+v", label)
		}
	}
	if !found {
		t.Fatal("expected deferred inline concern to remain as rejected evidence")
	}
}

func TestBuildReviewThreadContextIsBoundedAndThreadLocal(t *testing.T) {
	comments := []rawReviewComment{
		rawComment(1, 0, "reviewer", "make it IPv6", "2024-01-02T01:00:00Z"),
		rawComment(2, 1, "author", strings.Repeat("The generated rule passes string assertions but crashes the IPv6 consumer. ", 12), "2024-01-02T01:01:00Z"),
		rawComment(3, 1, "reviewer", "Use the enclosed bracket form expected by the parser.", "2024-01-02T01:02:00Z"),
		rawComment(4, 1, "author", "I reproduced that failure locally.", "2024-01-02T01:03:00Z"),
		rawComment(5, 1, "reviewer", "Please keep the regression fixture.", "2024-01-02T01:04:00Z"),
		rawComment(6, 1, "author", "Pushed another update.", "2024-01-02T01:05:00Z"),
		rawComment(99, 0, "other-reviewer", "unrelated concern", "2024-01-02T01:00:30Z"),
		rawComment(100, 99, "other-author", "unrelated explanation", "2024-01-02T01:01:30Z"),
	}
	got := buildReviewThreadContext(comments, "author")[1]
	if len(got) != maxThreadContextMessages {
		t.Fatalf("context messages = %d, want bound %d: %#v", len(got), maxThreadContextMessages, got)
	}
	total := 0
	for _, message := range got {
		if message.CommentID == 99 || message.CommentID == 100 || strings.Contains(message.Body, "unrelated") {
			t.Fatalf("cross-thread message leaked into context: %#v", got)
		}
		if len([]rune(message.Body)) > maxThreadMessageRunes {
			t.Fatalf("message exceeded per-message bound: %d", len([]rune(message.Body)))
		}
		total += len([]rune(message.Body))
	}
	if total > maxThreadContextRunes {
		t.Fatalf("context exceeded total bound: %d", total)
	}
	if got[0].Role != "pull_request_author" || got[1].Role != "reviewer" {
		t.Fatalf("speaker roles not explicit: %#v", got)
	}
}

func rawComment(id, inReplyTo int64, author, body, createdAt string) rawReviewComment {
	comment := rawReviewComment{ID: id, InReplyToID: inReplyTo, Body: body, CreatedAt: createdAt}
	comment.User.Login = author
	return comment
}

func TestBuildCasesAuthorOnlyThreadCannotCreateGold(t *testing.T) {
	dir := t.TempDir()
	pull := `{
  "number": 7,
  "title": "explain generated rules",
  "html_url": "https://github.com/acme/r/pull/7",
  "base": {"sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
  "head": {"sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
  "user": {"login": "pull-author"}
}`
	reviews := `[
  {"id": 10, "user": {"login": "pull-author"}, "body": "", "state": "COMMENTED", "commit_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "submitted_at": "2024-01-02T01:00:00Z"}
]`
	comments := `[
  {"id": 11, "pull_request_review_id": 10, "user": {"login": "pull-author"}, "body": "Use enclosed brackets for IPv6 or the generated rule crashes the consumer.", "path": "rules.go", "line": 10, "commit_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "created_at": "2024-01-02T01:01:00Z"},
  {"id": 12, "pull_request_review_id": 10, "in_reply_to_id": 11, "user": {"login": "PULL-AUTHOR"}, "body": "The string assertion passed even though the real parser rejected it.", "path": "rules.go", "line": 10, "commit_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "created_at": "2024-01-02T01:02:00Z"}
]`
	for name, body := range map[string]string{
		"pull.json": pull, "reviews.json": reviews, "review-comments.json": comments,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	router := &scope.Router{Candidates: []scope.Candidate{{
		ID: "person-maintainer", AdversaryName: "person-maintainer", Mission: "Everything is in scope. Do not exclude nits.",
	}}}
	got, err := BuildCasesFromCacheFiltered("acme", "r", 7, dir, nil, router, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("cases = %d, want one author-only evidence case", len(got))
	}
	for _, label := range got[0].Labels.ExpectedConcerns {
		if label.Approved || label.OwnerAdversary != "" || label.Scope != string(scope.OutOfScope) {
			t.Fatalf("author-only thread created gold: %+v", label)
		}
		if label.ScopeMethod != "thread-metadata" {
			t.Fatalf("author rejection lost thread provenance: %+v", label)
		}
	}
}

func TestBuildCasesRejectsPullAuthorSelfReview(t *testing.T) {
	dir := t.TempDir()
	pull := `{
  "number": 11666,
  "title": "Use stable TypeScript compiler",
  "html_url": "https://github.com/acme/r/pull/11666",
  "base": {"sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
  "head": {"sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
  "user": {"login": "pull-author"}
}`
	reviews := `[
  {"id": 101, "user": {"login": "pull-author"}, "body": "", "state": "COMMENTED", "commit_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "submitted_at": "2024-01-02T01:00:00Z"}
]`
	comments := `[
  {"id": 102, "pull_request_review_id": 101, "user": {"login": "PULL-AUTHOR"}, "body": "This explicit return type keeps declaration emit from naming an internal package path.", "path": "public.ts", "line": 7, "commit_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "created_at": "2024-01-02T01:01:00Z"}
]`
	for name, body := range map[string]string{
		"pull.json": pull, "reviews.json": reviews, "review-comments.json": comments,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	router := &scope.Router{
		Candidates: []scope.Candidate{{ID: "typescript", AdversaryName: "typescript", Mission: "TypeScript declaration quality"}},
		UseLLM:     false,
	}
	got, err := BuildCasesFromCacheFiltered("acme", "r", 11666, dir, nil, router, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("cases = %d, want one self-review evidence case", len(got))
	}
	labels := got[0].Labels.ExpectedConcerns
	if len(labels) != 1 {
		t.Fatalf("labels = %d, want one rejected self-review label", len(labels))
	}
	label := labels[0]
	if label.Approved || label.Scope != string(scope.OutOfScope) || label.OwnerAdversary != "" {
		t.Fatalf("pull author self-review became gold: %+v", label)
	}
	if label.ScopeMethod != "thread-metadata" || !strings.Contains(label.ScopeReason, "pull request author") {
		t.Fatalf("self-review provenance was not retained: %+v", label)
	}
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

func TestBuildCasesRetainsIndependentInScopeReviewsNewestFirst(t *testing.T) {
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
	if len(got) != 2 {
		t.Fatalf("cases = %d, want one case per distinct reviewed SHA", len(got))
	}
	var approved []*cases.Case
	for _, candidate := range got {
		for _, label := range candidate.Labels.ExpectedConcerns {
			if label.Approved {
				approved = append(approved, candidate)
				break
			}
		}
	}
	if len(approved) != 2 {
		t.Fatalf("approved cases = %d, want both independently reviewed states", len(approved))
	}
	if approved[0].ReviewEvent.ReviewedSHA != "cccccccccccccccccccccccccccccccccccccccc" ||
		approved[1].ReviewEvent.ReviewedSHA != "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" {
		t.Fatalf("reviewed SHAs = [%q, %q], want newest then older", approved[0].ReviewEvent.ReviewedSHA, approved[1].ReviewEvent.ReviewedSHA)
	}
	if !containsString(approved[0].ReviewEvent.Reviewers, "new-reviewer") || !containsString(approved[0].ReviewEvent.Reviewers, "maintainer-contributor") {
		t.Fatalf("first reviewers = %#v, want both reviews of the newest SHA", approved[0].ReviewEvent.Reviewers)
	}
	if len(approved[1].ReviewEvent.Reviewers) != 1 || approved[1].ReviewEvent.Reviewers[0] != "old-reviewer" {
		t.Fatalf("second reviewers = %#v, want older reviewer concern", approved[1].ReviewEvent.Reviewers)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
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
