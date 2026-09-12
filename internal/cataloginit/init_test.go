package cataloginit

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
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
		"adversaries/data-integrity/README.md",
		"adversaries/migrations-and-backfills/README.md",
		"adversaries/tenant-and-access-boundaries/README.md",
		"adversaries/reliability-and-concurrency/README.md",
		"adversaries/compatibility/README.md",
		"adversaries/operability/README.md",
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
	var catalog struct {
		Spec struct {
			Adversaries []struct {
				ID      string `yaml:"id"`
				Path    string `yaml:"path"`
				Summary string `yaml:"summary"`
			} `yaml:"adversaries"`
		} `yaml:"spec"`
	}
	if err := yaml.Unmarshal(manifest, &catalog); err != nil {
		t.Fatalf("parse generated manifest: %v", err)
	}
	if len(catalog.Spec.Adversaries) != len(starterAdversaries) {
		t.Fatalf("manifest adversaries=%d want %d", len(catalog.Spec.Adversaries), len(starterAdversaries))
	}
	for index, adversary := range starterAdversaries {
		entry := catalog.Spec.Adversaries[index]
		if entry.ID != adversary.Slug || entry.Path != "adversaries/"+adversary.Slug || entry.Summary != adversary.Summary {
			t.Fatalf("manifest adversary[%d]=%+v", index, entry)
		}
		brief, err := os.ReadFile(filepath.Join(destination, "adversaries", adversary.Slug, "README.md"))
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{adversary.Title, adversary.Summary, "Evidence standard", "Learning notes"} {
			if !strings.Contains(string(brief), want) {
				t.Fatalf("%s brief missing %q", adversary.Slug, want)
			}
		}
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
	for _, want := range []string{"Generated catalog with 6 starter adversaries", "git init", "git commit", "'/tmp/private catalog'"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("output %q missing %q", output.String(), want)
		}
	}
}
