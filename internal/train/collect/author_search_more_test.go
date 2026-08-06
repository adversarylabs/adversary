package collect

import (
	"testing"

	"github.com/adversarylabs/adversary/internal/githubapi"
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
	if !IsRateLimit(&githubapi.RateLimitError{Message: "API rate limit exceeded for user"}) {
		t.Fatal()
	}
	if IsRateLimit(simpleErr("no PRs found")) {
		t.Fatal()
	}
}

type simpleErr string

func (e simpleErr) Error() string { return string(e) }
