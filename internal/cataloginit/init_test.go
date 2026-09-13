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
		"adversary.train.yaml",
		".gitignore",
		"README.md",
		"adversaries/data-integrity/README.md",
		"adversaries/migrations-and-backfills/README.md",
		"adversaries/tenant-and-access-boundaries/README.md",
		"adversaries/reliability-and-concurrency/README.md",
		"adversaries/compatibility/README.md",
		"adversaries/operability/README.md",
		"adversaries/engineering-conventions/README.md",
		"adversaries/tenant-and-access-boundaries/adversary.yaml",
		"adversaries/tenant-and-access-boundaries/package.json",
		"adversaries/tenant-and-access-boundaries/package-lock.json",
		"adversaries/tenant-and-access-boundaries/src/index.ts",
		"adversaries/tenant-and-access-boundaries/dist/index.js",
		"adversaries/tenant-and-access-boundaries/test/index.test.ts",
		"adversaries/tenant-and-access-boundaries/docs/scope.md",
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
	ignore, err := os.ReadFile(filepath.Join(destination, ".gitignore"))
	if err != nil || !strings.Contains(string(ignore), "node_modules/") || !strings.Contains(string(ignore), ".adversary/") {
		t.Fatalf("gitignore=%q err=%v", ignore, err)
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
		for _, name := range []string{"adversary.yaml", "package.json", "package-lock.json", "src/index.ts", "dist/index.js", "test/index.test.ts", "docs/scope.md"} {
			if _, err := os.Stat(filepath.Join(destination, "adversaries", adversary.Slug, filepath.FromSlash(name))); err != nil {
				t.Fatalf("%s is not runnable; missing %s: %v", adversary.Slug, name, err)
			}
		}
	}
	operability, err := os.ReadFile(filepath.Join(destination, "adversaries", "operability", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"User-facing errors", "concrete recovery step", "underlying cause", "leak secrets", "logs, metrics, and traces", "identifiers operators need"} {
		if !strings.Contains(string(operability), want) {
			t.Fatalf("operability brief missing %q:\n%s", want, operability)
		}
	}
}

func TestUpgradePreservesPoliciesAndMakesEntriesRunnable(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "adversarylabs.yaml"), []byte("kind: AdversaryCatalog\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte("custom-cache/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "adversaries", "operability")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	policy := "# Operability\n\n## Purpose\n\nKeep failures actionable.\n"
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte(policy), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := Upgrade(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Upgraded) != 1 || result.Upgraded[0] != "operability" {
		t.Fatalf("result=%+v", result)
	}
	if !result.IgnoreUpdated {
		t.Fatal("upgrade did not harden the catalog .gitignore")
	}
	ignore, err := os.ReadFile(filepath.Join(root, ".gitignore"))
	if err != nil || !strings.Contains(string(ignore), "custom-cache/") || !strings.Contains(string(ignore), "node_modules/") {
		t.Fatalf("gitignore=%q err=%v", ignore, err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "README.md"))
	if err != nil || string(raw) != policy {
		t.Fatalf("README changed: %q err=%v", raw, err)
	}
	for _, name := range []string{"adversary.yaml", "package.json", "src/index.ts", "dist/index.js", "test/index.test.ts"} {
		if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(name))); err != nil {
			t.Fatalf("missing %s: %v", name, err)
		}
	}
	again, err := Upgrade(root)
	if err != nil || len(again.Upgraded) != 0 || again.IgnoreUpdated {
		t.Fatalf("second upgrade=%+v err=%v", again, err)
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
	for _, want := range []string{"Generated catalog with 7 starter adversaries", "git init", "git commit", "'/tmp/private catalog'", "adversary catalog train", "adversary catalog train review"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("output %q missing %q", output.String(), want)
		}
	}
}
