package oci

import "testing"

func TestParseReferenceDefaults(t *testing.T) {
	tests := []struct {
		input      string
		registry   string
		repository string
		tag        string
		locator    string
	}{
		{
			input:      "security-reviewer",
			registry:   DefaultRegistry,
			repository: "library/security-reviewer",
			tag:        "latest",
			locator:    "registry.adversarylabs.ai/library/security-reviewer:latest",
		},
		{
			input:      "adversarylabs/security-reviewer",
			registry:   DefaultRegistry,
			repository: "adversarylabs/security-reviewer",
			tag:        "latest",
			locator:    "registry.adversarylabs.ai/adversarylabs/security-reviewer:latest",
		},
		{
			input:      "ghcr.io/acme/security-reviewer",
			registry:   "ghcr.io",
			repository: "acme/security-reviewer",
			tag:        "latest",
			locator:    "ghcr.io/acme/security-reviewer:latest",
		},
		{
			input:      "localhost:5000/security-reviewer:v1",
			registry:   "localhost:5000",
			repository: "security-reviewer",
			tag:        "v1",
			locator:    "localhost:5000/security-reviewer:v1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			ref, err := ParseReference(tt.input)
			if err != nil {
				t.Fatal(err)
			}
			if ref.Registry != tt.registry || ref.Repository != tt.repository || ref.Tag != tt.tag {
				t.Fatalf("ParseReference(%q) = %#v", tt.input, ref)
			}
			if got := ref.Locator(); got != tt.locator {
				t.Fatalf("locator = %q, want %q", got, tt.locator)
			}
		})
	}
}

func TestParseReferenceUsesRegistryHostOverride(t *testing.T) {
	t.Setenv("ADVERSARY_REGISTRY_HOST", "localhost:5000")
	ref, err := ParseReference("security-reviewer")
	if err != nil {
		t.Fatal(err)
	}
	if ref.Registry != "localhost:5000" {
		t.Fatalf("Registry = %q", ref.Registry)
	}
	if got := ref.Locator(); got != "localhost:5000/library/security-reviewer:latest" {
		t.Fatalf("Locator = %q", got)
	}
}
