package cataloginit

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreateGeneratesLocalCatalog(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "private-adversaries")
	result, err := Create(Options{Destination: destination})
	if err != nil {
		t.Fatal(err)
	}
	if result.Location != destination {
		t.Fatalf("location=%q want %q", result.Location, destination)
	}
	for _, name := range []string{
		"adversarylabs.yaml",
		"README.md",
		"adversaries/.gitkeep",
		"evaluations/.gitkeep",
		"exceptions/.gitkeep",
	} {
		if _, err := os.Stat(filepath.Join(destination, filepath.FromSlash(name))); err != nil {
			t.Fatalf("missing %s: %v", name, err)
		}
	}
	manifest, err := os.ReadFile(filepath.Join(destination, "adversarylabs.yaml"))
	if err != nil || !strings.Contains(string(manifest), "kind: AdversaryCatalog") {
		t.Fatalf("manifest=%q err=%v", manifest, err)
	}
}

func TestCreateRefusesExistingDestination(t *testing.T) {
	destination := t.TempDir()
	if _, err := Create(Options{Destination: destination}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("err=%v", err)
	}
}

func TestRenderSuccessIncludesNextSteps(t *testing.T) {
	var output bytes.Buffer
	RenderSuccess(&output, Result{Location: "/tmp/private catalog"}, "linux")
	for _, want := range []string{"Generated catalog", "git init", "git commit", "'/tmp/private catalog'"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("output %q missing %q", output.String(), want)
		}
	}
}
