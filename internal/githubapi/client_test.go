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
	q := BuildAuthorPRSearchQuery("alice", "reviewed-by", []string{"acme"}, "2024-01-01", true)
	for _, want := range []string{"type:pr", "is:merged", "reviewed-by:alice", "org:acme", "merged:>=2024-01-01"} {
		if !strings.Contains(q, want) {
			t.Fatalf("%s missing %s", q, want)
		}
	}
}

func TestParseNextLink(t *testing.T) {
	got := ParseLinkPage(`<https://api.github.com/r?page=2>; rel="next", <https://api.github.com/r?page=5>; rel="last"`)
	if !strings.Contains(got, "page=2") {
		t.Fatalf("%q", got)
	}
}
