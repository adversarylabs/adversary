package githubapi

import (
	"fmt"
	"os"
	"strings"
)

// LookupEnv is os.LookupEnv for callers that must not import os directly.
func LookupEnv(key string) (string, bool) { return os.LookupEnv(key) }

// TokenFromEnv resolves a GitHub token in design order.
// ADVERSARY_GITHUB_TOKEN → GITHUB_TOKEN → GH_TOKEN.
func TokenFromEnv() string {
	return TokenFromLookup(os.LookupEnv)
}

// TokenFromLookup is the testable form of TokenFromEnv.
func TokenFromLookup(lookup func(string) (string, bool)) string {
	for _, key := range []string{"ADVERSARY_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"} {
		if v, ok := lookup(key); ok {
			if t := strings.TrimSpace(v); t != "" {
				return t
			}
		}
	}
	return ""
}

// RequireToken returns a token or a clear error for operators.
func RequireToken() (string, error) {
	t := TokenFromEnv()
	if t == "" {
		return "", fmt.Errorf("GitHub token required: set ADVERSARY_GITHUB_TOKEN, GITHUB_TOKEN, or GH_TOKEN")
	}
	return t, nil
}
