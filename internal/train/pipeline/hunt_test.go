package pipeline

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/adversarylabs/adversary/internal/githubapi"
	"github.com/adversarylabs/adversary/internal/train/cases"
	"github.com/adversarylabs/adversary/internal/train/collect"
	"github.com/adversarylabs/adversary/internal/train/repos"
	"github.com/adversarylabs/adversary/internal/train/runner"
	"github.com/adversarylabs/adversary/internal/train/state"
)

func TestNormalizeConcurrency(t *testing.T) {
	t.Parallel()
	if got := normalizeConcurrency(0); got != defaultHuntConcurrency {
		t.Fatalf("default: got %d", got)
	}
	if got := normalizeConcurrency(-1); got != defaultHuntConcurrency {
		t.Fatalf("neg: got %d", got)
	}
	if got := normalizeConcurrency(3); got != 3 {
		t.Fatalf("3: got %d", got)
	}
	if got := normalizeConcurrency(100); got != maxHuntConcurrency {
		t.Fatalf("cap: got %d", got)
	}
}

func TestCatalogRepoWindowBoundsAndWraps(t *testing.T) {
	t.Parallel()
	catalog := []repos.Repo{
		{Owner: "o", Name: "zero"},
		{Owner: "o", Name: "one"},
		{Owner: "o", Name: "two"},
		{Owner: "o", Name: "three"},
	}
	got := catalogRepoWindow(catalog, 3, 3)
	want := []string{"three", "zero", "one"}
	if len(got) != len(want) {
		t.Fatalf("window length = %d, want %d", len(got), len(want))
	}
	for i, repo := range got {
		if repo.Name != want[i] {
			t.Fatalf("window[%d] = %q, want %q", i, repo.Name, want[i])
		}
	}

	got = catalogRepoWindow(catalog, 0, 20)
	if len(got) != len(catalog) {
		t.Fatalf("clamped window length = %d, want %d", len(got), len(catalog))
	}
}

func TestParallelHuntProbesOneRotatingMaxTurnsWindow(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	transport := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`[]`)),
		}, nil
	})

	client := githubapi.NewClient("test")
	client.HTTP = &http.Client{Transport: transport}
	client.RESTBase = "https://api.test"
	collect.SetDefaultClient(client)
	t.Cleanup(func() { collect.SetDefaultClient(nil) })

	var catalog []repos.Repo
	for i := 0; i < 10; i++ {
		catalog = append(catalog, repos.Repo{Owner: "owner", Name: fmt.Sprintf("repo-%d", i)})
	}
	dataRoot := t.TempDir()
	opts := Options{Context: context.Background(), AdversaryName: "lang/typescript", Concurrency: 2}
	progress := func(string, ...any) {}

	first := runParallelHunt(context.Background(), opts, catalog, dataRoot, 1, 3, nil, nil, progress, nil)
	if first.interrupted != nil {
		t.Fatal(first.interrupted)
	}
	second := runParallelHunt(context.Background(), opts, catalog, dataRoot, 1, 3, nil, nil, progress, nil)
	if second.interrupted != nil {
		t.Fatal(second.interrupted)
	}

	mu.Lock()
	defer mu.Unlock()
	want := []string{
		"/repos/owner/repo-0/pulls", "/repos/owner/repo-1/pulls", "/repos/owner/repo-2/pulls",
		"/repos/owner/repo-3/pulls", "/repos/owner/repo-4/pulls", "/repos/owner/repo-5/pulls",
	}
	if len(paths) != len(want) {
		t.Fatalf("GitHub list requests = %d, want %d: %v", len(paths), len(want), paths)
	}
	seen := map[string]int{}
	for _, path := range paths {
		seen[path]++
	}
	for _, path := range want {
		if seen[path] != 1 {
			t.Fatalf("request count for %q = %d, want 1; all requests: %v", path, seen[path], paths)
		}
	}
}

func TestGitHubEventsHuntUsesOneBatchThenHydratesFromGitHub(t *testing.T) {
	var mu sync.Mutex
	var githubPaths []string
	githubTransport := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		githubPaths = append(githubPaths, r.URL.Path)
		mu.Unlock()
		body := `[]`
		if r.URL.Path == "/repos/acme/api/pulls/42" {
			body = `{
				"number":42,
				"html_url":"https://github.com/acme/api/pull/42",
				"title":"canonical title from GitHub",
				"merged_at":"2026-08-17T12:00:00Z",
				"user":{"login":"human-author"},
				"base":{"sha":"base-sha"},
				"head":{"sha":"head-sha"}
			}`
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(body)),
		}, nil
	})
	githubClient := githubapi.NewClient("test")
	githubClient.HTTP = &http.Client{Transport: githubTransport}
	githubClient.RESTBase = "https://api.test"
	collect.SetDefaultClient(githubClient)
	t.Cleanup(func() { collect.SetDefaultClient(nil) })

	eventsRequests := 0
	eventsClient := &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		eventsRequests++
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body: io.NopCloser(strings.NewReader(
				`{"repo_name":"acme/api","number":43,"title":"already seen"}` + "\n" +
					`{"repo_name":"acme/api","number":42,"title":"mirror title is not evidence"}` + "\n")),
		}, nil
	})}

	catalog := []repos.Repo{
		{Owner: "acme", Name: "api"},
		{Owner: "other", Name: "tool"},
		{Owner: "third", Name: "repo"},
	}
	opts := Options{
		Context:            context.Background(),
		AdversaryName:      "lang/typescript",
		DiscoveryMode:      "github_events",
		GitHubEventsClient: eventsClient,
		Concurrency:        1,
	}
	dataRoot := t.TempDir()
	store, err := state.LoadDiscovery(dataRoot, "acme", "api")
	if err != nil {
		t.Fatal(err)
	}
	store.Record(43, "already seen", "https://github.com/acme/api/pull/43", state.OutcomeNoInScope, "prior run")
	if err := store.Save(); err != nil {
		t.Fatal(err)
	}
	out := runParallelHunt(context.Background(), opts, catalog, dataRoot, 1, 3, nil, nil, func(string, ...any) {}, nil)
	if out.interrupted != nil {
		t.Fatal(out.interrupted)
	}
	if eventsRequests != 1 {
		t.Fatalf("events requests=%d want 1", eventsRequests)
	}
	mu.Lock()
	defer mu.Unlock()
	wantPaths := []string{
		"/repos/acme/api/pulls/42",
		"/repos/acme/api/pulls/42/reviews",
		"/repos/acme/api/pulls/42/comments",
	}
	for _, want := range wantPaths {
		found := false
		for _, got := range githubPaths {
			if got == want {
				found = true
			}
			if strings.HasSuffix(got, "/pulls") {
				t.Fatalf("unexpected GitHub list discovery request: %s", got)
			}
		}
		if !found {
			t.Fatalf("missing canonical hydration request %s; got %v", want, githubPaths)
		}
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestDiscoveryStoreConcurrentRecord(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s, err := state.LoadDiscovery(dir, "o", "r")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 1; i <= 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			s.Record(n, "t", "u", state.OutcomeNoInScope, "note")
			_ = s.Save()
			_ = s.Seen(n)
			_ = s.SeenSet()
		}(i)
	}
	wg.Wait()
	if len(s.ListNumbers()) != 50 {
		t.Fatalf("want 50 records, got %d", len(s.ListNumbers()))
	}
}

func TestLockLocalPackageSerializes(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	var order []int
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			unlock := runner.LockLocalPackage(dir)
			mu.Lock()
			order = append(order, id)
			mu.Unlock()
			time.Sleep(30 * time.Millisecond)
			mu.Lock()
			order = append(order, id+10)
			mu.Unlock()
			unlock()
		}(i)
	}
	wg.Wait()
	// Fully nested: first complete (id, id+10) before second starts.
	if len(order) != 4 {
		t.Fatalf("order %#v", order)
	}
	// First two entries must be same id and id+10 (serialized).
	if order[1] != order[0]+10 {
		t.Fatalf("not serialized: %#v", order)
	}
	if order[3] != order[2]+10 {
		t.Fatalf("not serialized: %#v", order)
	}
}

func TestApplyCollectResultPinned(t *testing.T) {
	t.Parallel()
	out := &huntOutcome{}
	c := &cases.Case{ID: "c1"}
	applyCollectResult(out, collectResult{kept: []*cases.Case{c}, inScopeN: 0}, true, 1)
	if len(out.caseList) != 1 {
		t.Fatalf("pinned empty gold should still keep case")
	}
	out2 := &huntOutcome{}
	applyCollectResult(out2, collectResult{kept: []*cases.Case{c}, inScopeN: 1}, false, 1)
	if out2.prsWithInScope != 1 {
		t.Fatalf("in-scope count")
	}
}

func TestApplyCollectResultEnforcesTargetSequentially(t *testing.T) {
	t.Parallel()
	out := &huntOutcome{}
	persisted := 0
	for i := 0; i < 5; i++ {
		c := &cases.Case{ID: fmt.Sprintf("c%d", i)}
		if applyCollectResult(out, collectResult{kept: []*cases.Case{c}, inScopeN: 1}, false, 1) {
			persisted++
		}
	}
	if out.prsWithInScope != 1 || len(out.caseList) != 1 || persisted != 1 {
		t.Fatalf("cap not enforced: prs=%d cases=%d persisted=%d", out.prsWithInScope, len(out.caseList), persisted)
	}
}

func TestApplyCollectResultEnforcesTargetConcurrently(t *testing.T) {
	t.Parallel()
	out := &huntOutcome{}
	var mu sync.Mutex
	persisted := 0
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c := &cases.Case{ID: fmt.Sprintf("c%d", i)}
			mu.Lock()
			if applyCollectResult(out, collectResult{kept: []*cases.Case{c}, inScopeN: 1}, false, 1) {
				persisted++
			}
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	if out.prsWithInScope != 1 || len(out.caseList) != 1 || persisted != 1 {
		t.Fatalf("cap not enforced: prs=%d cases=%d persisted=%d", out.prsWithInScope, len(out.caseList), persisted)
	}
}
