package cmd

import "testing"

func TestHostedNamespaceRegistryBoundary(t *testing.T) {
	for _, host := range []string{"registry.adversarylabs.ai", "registry.staging.adversarylabs.ai", "localhost:8787"} {
		if !isHostedNamespaceRegistry(host) {
			t.Fatalf("%q should be hosted", host)
		}
	}
	for _, host := range []string{"ghcr.io", "registry.example", "adversarylabs.ai.example"} {
		if isHostedNamespaceRegistry(host) {
			t.Fatalf("external registry %q was treated as hosted", host)
		}
	}
}
