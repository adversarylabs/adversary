package cmd

import "testing"

func TestCanonicalCatalogReference(t *testing.T) {
	tests := map[string]string{
		"depot/ci":                            "ci/depot",
		" depot/ci:0.0.16 ":                   "ci/depot:0.0.16",
		"depot/ci@sha256:0123456789abcdef":    "ci/depot@sha256:0123456789abcdef",
		"ci/depot":                            "ci/depot",
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
