package collect

import "testing"

func TestSanitizePreservesErrorsWhenTokensAreUnset(t *testing.T) {
	for _, name := range []string{"GITHUB_TOKEN", "GH_TOKEN", "ADVERSARY_GITHUB_TOKEN"} {
		t.Setenv(name, "")
	}
	message := "github API rate limit exceeded (resets in 15m0s)"
	if got := sanitize(message); got != message {
		t.Fatalf("got %q, want readable error %q", got, message)
	}
}

func TestSanitizeRedactsConfiguredTokens(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "github-secret")
	t.Setenv("GH_TOKEN", "")
	t.Setenv("ADVERSARY_GITHUB_TOKEN", "adversary-secret")
	if got := sanitize("request github-secret failed; adversary-secret"); got != "request *** failed; ***" {
		t.Fatalf("unexpected sanitized error: %q", got)
	}
}
