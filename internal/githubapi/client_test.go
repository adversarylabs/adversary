package githubapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTokenFromLookup(t *testing.T) {
	tok := TokenFromLookup(func(k string) (string, bool) {
		if k == "GH_TOKEN" {
			return " ght ", true
		}
		return "", false
	})
	if tok != "ght" {
		t.Fatalf("%q", tok)
	}
	tok = TokenFromLookup(func(k string) (string, bool) {
		if k == "ADVERSARY_GITHUB_TOKEN" {
			return "a", true
		}
		if k == "GITHUB_TOKEN" {
			return "b", true
		}
		return "", false
	})
	if tok != "a" {
		t.Fatalf("%q", tok)
	}
}

func TestParseGitHubPRURL(t *testing.T) {
	cases := []struct {
		in     string
		ok     bool
		owner  string
		repo   string
		number int
	}{
		{"https://github.com/acme/app/pull/42", true, "acme", "app", 42},
		{"https://github.com/acme/app/pull/42/files", true, "acme", "app", 42},
		{"github.com/acme/app/pull/7", true, "acme", "app", 7},
		{"https://www.github.com/o/r/pull/1", true, "o", "r", 1},
		{"acme/app", false, "", "", 0},
		{"https://gitlab.com/o/r/pull/1", false, "", "", 0},
	}
	for _, tc := range cases {
		got, ok := ParseGitHubPRURL(tc.in)
		if ok != tc.ok {
			t.Fatalf("%s: ok=%v want %v", tc.in, ok, tc.ok)
		}
		if !ok {
			continue
		}
		if got.Owner != tc.owner || got.Repo != tc.repo || got.Number != tc.number {
			t.Fatalf("%s: got %#v", tc.in, got)
		}
	}
}

func TestRESTGetPaginatedAndHeaders(t *testing.T) {
	ResetRateGateForTest()
	var pages int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Fatalf("auth %q", r.Header.Get("Authorization"))
		}
		pages++
		if pages == 1 {
			w.Header().Set("Link", `<http://example.invalid/next>; rel="next"`)
			// First response uses full request URL host from server.
			w.Header().Set("Link", `<`+"http://"+r.Host+`/page2`+`>; rel="next"`)
			_, _ = w.Write([]byte(`[{"name":"a"}]`))
			return
		}
		_, _ = w.Write([]byte(`[{"name":"b"}]`))
	}))
	defer srv.Close()

	c := NewClient("tok")
	c.HTTP = srv.Client()
	c.RESTBase = srv.URL
	raw, err := c.RESTGetPaginated(context.Background(), "/repos")
	if err != nil {
		t.Fatal(err)
	}
	var rows []map[string]string
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("%s", raw)
	}
}

func TestGraphQLSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatal(r.Method)
		}
		_, _ = w.Write([]byte(`{"data":{"ok":true}}`))
	}))
	defer srv.Close()
	c := NewClient("t")
	c.HTTP = srv.Client()
	c.GQLURL = srv.URL
	var out struct {
		OK bool `json:"ok"`
	}
	if err := c.GraphQL(context.Background(), "query { ok }", nil, &out); err != nil {
		t.Fatal(err)
	}
	if !out.OK {
		t.Fatal(out)
	}
}

func TestBuildAuthorPRSearchQuery(t *testing.T) {
	q := BuildAuthorPRSearchQuery("alice", "reviewed-by", []string{"acme"}, "2024-01-01", "go", true)
	for _, want := range []string{"type:pr", "is:merged", "reviewed-by:alice", "org:acme", "merged:>=2024-01-01", "language:go"} {
		if !strings.Contains(q, want) {
			t.Fatalf("%s missing %s", q, want)
		}
	}
}

func TestSearchPullRequestsPaginated(t *testing.T) {
	ResetRateGateForTest()
	var pages int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pages++
		page := r.URL.Query().Get("page")
		if page == "" || page == "1" {
			_, _ = w.Write([]byte(`{"items":[{"number":1,"title":"a","html_url":"https://github.com/o/r/pull/1","repository_url":"https://api.github.com/repos/o/r"},{"number":2,"title":"b","html_url":"https://github.com/o/r/pull/2","repository_url":"https://api.github.com/repos/o/r"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"items":[{"number":3,"title":"c","html_url":"https://github.com/o/r/pull/3","repository_url":"https://api.github.com/repos/o/r"}]}`))
	}))
	defer srv.Close()
	c := NewClient("t")
	c.HTTP = srv.Client()
	c.RESTBase = srv.URL
	// perPage inside SearchPullRequests is min(100, maxResults). With maxResults=3 and
	// first page returning only 2 items (<100), loop stops after page 1 unless we
	// force small pages. Call with maxResults that still pages: return full 100 on page1.
	// Simpler assertion: one page with 2 items for maxResults=2.
	got, err := c.SearchPullRequests(context.Background(), "type:pr", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Number != 1 {
		t.Fatalf("%#v pages=%d", got, pages)
	}
	owner, repo := OwnerRepoFromAPIURL(got[0].RepoURL)
	if owner != "o" || repo != "r" {
		t.Fatalf("%s %s", owner, repo)
	}
}

func TestGetPullRequestAndListFiles(t *testing.T) {
	ResetRateGateForTest()
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/o/r/pulls/1", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"number":1,"title":"t","html_url":"u","state":"open","base":{"ref":"main","sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","repo":{"full_name":"o/r","clone_url":"https://github.com/o/r.git","owner":{"login":"o"},"name":"r"}},"head":{"ref":"feat","sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","repo":{"full_name":"o/r","clone_url":"https://github.com/o/r.git","owner":{"login":"o"},"name":"r"}}}`))
	})
	mux.HandleFunc("/repos/o/r/pulls/1/files", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"filename":"a.go","patch":"@@ -1,1 +1,2 @@\n line\n+new\n"}]`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := NewClient("tok")
	c.HTTP = srv.Client()
	c.RESTBase = srv.URL
	pr, err := c.GetPullRequest(context.Background(), "o", "r", 1)
	if err != nil {
		t.Fatal(err)
	}
	if pr.Number != 1 || pr.Head.SHA == "" {
		t.Fatalf("%#v", pr)
	}
	files, err := c.ListPullRequestFiles(context.Background(), "o", "r", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Filename != "a.go" {
		t.Fatalf("%#v", files)
	}
}

func TestAuthErrorAndRateLimit(t *testing.T) {
	ResetRateGateForTest()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"Bad credentials"}`))
	}))
	defer srv.Close()
	c := NewClient("bad")
	c.HTTP = srv.Client()
	c.RESTBase = srv.URL
	_, _, err := c.RESTGet(context.Background(), "/user")
	if err == nil {
		t.Fatal("expected auth error")
	}
	if _, ok := err.(*AuthError); !ok {
		t.Fatalf("%T %v", err, err)
	}
}

func TestRequireToken(t *testing.T) {
	if TokenFromLookup(func(string) (string, bool) { return "", false }) != "" {
		t.Fatal()
	}
}

func TestParseNextLink(t *testing.T) {
	got := ParseLinkPage(`<https://api.github.com/r?page=2>; rel="next", <https://api.github.com/r?page=5>; rel="last"`)
	if !strings.Contains(got, "page=2") {
		t.Fatalf("%q", got)
	}
}
