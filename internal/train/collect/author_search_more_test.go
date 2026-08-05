package collect

import (
	"testing"
)

func TestDiscoverPRsByAuthorValidation(t *testing.T) {
	_, err := DiscoverPRsByAuthor(AuthorSearchOpts{})
	if err == nil {
		t.Fatal("expected authors required")
	}
	_, err = DiscoverPRsByAuthor(AuthorSearchOpts{Authors: []string{"x"}, Roles: []string{"not-a-role"}})
	if err == nil {
		t.Fatal("expected bad role")
	}
}

func TestBuildAuthorSkipSet(t *testing.T) {
	m := BuildAuthorSkipSet([]string{"a/b#1", "a/b#2"})
	if !m["a/b#1"] || len(m) != 2 {
		t.Fatalf("%v", m)
	}
}

func TestIsRateLimitText(t *testing.T) {
	if !isRateLimitText("API rate limit exceeded for user") {
		t.Fatal()
	}
	if isRateLimitText("no PRs found") {
		t.Fatal()
	}
	rl := parseRateLimit([]byte(`{"message":"secondary rate limit"}`))
	if rl == nil {
		t.Fatal("secondary")
	}
}
