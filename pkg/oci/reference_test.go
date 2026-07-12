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

func TestParseReferenceRejectsInvalid(t *testing.T) {
	long := make([]byte, 256)
	for i := range long {
		long[i] = 'a'
	}
	for _, input := range []string{"UPPER/repo", "repo@@sha256:" + string(make([]byte, 64)), "repo//name", "repo:bad tag", "repo\x00name", string(long)} {
		t.Run(input, func(t *testing.T) {
			if _, err := ParseReference(input); err == nil {
				t.Fatalf("accepted %q", input)
			}
		})
	}
}

func TestParseReferenceIPv6(t *testing.T) {
	r, err := ParseReference("[2001:db8::1]:5000/acme/tool:v1")
	if err != nil {
		t.Fatal(err)
	}
	if r.Registry != "[2001:db8::1]:5000" || r.Repository != "acme/tool" {
		t.Fatalf("reference = %#v", r)
	}
}

func FuzzParseReference(f *testing.F) {
	for _, seed := range []string{"repo", "ghcr.io/a/b:v1", "repo@@sha256:00", "a//b", "é", "e\u0301"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		ref, err := ParseReference(input)
		if err == nil {
			if _, err := ParseReference(ref.Locator()); err != nil {
				t.Fatalf("locator did not round trip: %v", err)
			}
		}
	})
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

func TestParseReferenceWithDefaultsIgnoresRegistryEnvironment(t *testing.T) {
	t.Setenv("ADVERSARY_REGISTRY_HOST", "poison.example")
	ref, err := ParseReferenceWithDefaults("security-reviewer:1.2.3", DefaultRegistry, DefaultNamespace)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := ref.Locator(), "registry.adversarylabs.ai/library/security-reviewer:1.2.3"; got != want {
		t.Fatalf("locator=%q want %q", got, want)
	}
}

func TestRegistryHostOverrideRejectsScheme(t *testing.T) {
	t.Setenv("ADVERSARY_REGISTRY_HOST", "http://localhost:5000")
	if _, err := ParseReference("security-reviewer"); err == nil {
		t.Fatal("registry host scheme was silently accepted")
	}
}
