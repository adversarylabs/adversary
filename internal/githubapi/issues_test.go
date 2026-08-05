package githubapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCreateIssue(t *testing.T) {
	var gotPath string
	var gotBody CreateIssueInput
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if r.Method != http.MethodPost {
			t.Fatalf("method %s", r.Method)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"number":   42,
			"html_url": "https://github.com/acme/torvalds-adversary/issues/42",
			"title":    gotBody.Title,
			"state":    "open",
		})
	}))
	defer srv.Close()

	c := NewClient("tok")
	c.RESTBase = srv.URL
	c.HTTP = srv.Client()
	issue, err := c.CreateIssue(context.Background(), "acme", "torvalds-adversary", CreateIssueInput{
		Title:  "train: miss for torvalds",
		Body:   "fix it",
		Labels: []string{"train"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/repos/acme/torvalds-adversary/issues" {
		t.Fatalf("path %s", gotPath)
	}
	if issue.Number != 42 || issue.HTMLURL == "" {
		t.Fatalf("%+v", issue)
	}
	if gotBody.Title != "train: miss for torvalds" {
		t.Fatalf("%+v", gotBody)
	}
}

func TestParseGitRemoteURL(t *testing.T) {
	cases := []struct {
		in, owner, name string
	}{
		{"https://github.com/acme/torvalds-adversary.git", "acme", "torvalds-adversary"},
		{"https://github.com/acme/torvalds-adversary", "acme", "torvalds-adversary"},
		{"git@github.com:acme/torvalds-adversary.git", "acme", "torvalds-adversary"},
		{"ssh://git@github.com/acme/torvalds-adversary.git", "acme", "torvalds-adversary"},
	}
	for _, tc := range cases {
		ref, err := ParseGitRemoteURL(tc.in)
		if err != nil {
			t.Fatalf("%s: %v", tc.in, err)
		}
		if ref.Owner != tc.owner || ref.Name != tc.name {
			t.Fatalf("%s → %+v want %s/%s", tc.in, ref, tc.owner, tc.name)
		}
	}
}
