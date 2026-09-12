package githubauth

import (
	"errors"
	"strings"
	"testing"
)

func TestRequireTokenFromSources(t *testing.T) {
	t.Run("environment takes precedence", func(t *testing.T) {
		ghCalled := false
		got, err := requireToken(func() string { return " environment-token " }, func() (string, error) {
			ghCalled = true
			return "gh-token", nil
		})
		if err != nil || got != "environment-token" {
			t.Fatalf("token = %q, err = %v", got, err)
		}
		if ghCalled {
			t.Fatal("gh fallback called despite configured environment token")
		}
	})

	t.Run("falls back to gh", func(t *testing.T) {
		got, err := requireToken(func() string { return "" }, func() (string, error) {
			return " gh-token\n", nil
		})
		if err != nil || got != "gh-token" {
			t.Fatalf("token = %q, err = %v", got, err)
		}
	})

	for _, tc := range []struct {
		name string
		gh   func() (string, error)
	}{
		{name: "gh unavailable", gh: func() (string, error) { return "", errors.New("unavailable") }},
		{name: "empty gh token", gh: func() (string, error) { return " \n", nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := requireToken(func() string { return "" }, tc.gh)
			if got != "" || err == nil {
				t.Fatalf("token = %q, err = %v", got, err)
			}
			if !strings.Contains(err.Error(), "gh auth login") {
				t.Fatalf("error = %q", err)
			}
		})
	}
}
