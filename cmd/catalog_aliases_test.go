package cmd

import "testing"

func TestCanonicalCatalogReference(t *testing.T) {
	tests := map[string]string{
		"depot/ci":                            "library/ci/depot",
		" depot/ci:0.0.16 ":                   "library/ci/depot:0.0.16",
		"depot/ci@sha256:0123456789abcdef":    "library/ci/depot@sha256:0123456789abcdef",
		"ci/depot":                            "library/ci/depot",
		"go/security":                         "library/go/security",
		"go/security:0.0.22":                  "library/go/security:0.0.22",
		"library/go/security":                 "library/go/security",
		"adversarylabs/go/security":           "adversarylabs/go/security",
		"./depot/ci":                          "./depot/ci",
		"registry.example/depot/ci":           "registry.example/depot/ci",
		"depot/ci-extra":                      "depot/ci-extra",
		"another-domain/another-adversary:v1": "another-domain/another-adversary:v1",
	}
	for input, want := range tests {
		t.Run(input, func(t *testing.T) {
			if got := canonicalCatalogReference(input); got != want {
				t.Fatalf("canonicalCatalogReference(%q) = %q, want %q", input, got, want)
			}
		})
	}
}
