package adversary

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadManifest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "adversary.yaml")
	data := []byte(`name: adversarylabs/github-actions
version: 0.1.0
description: Finds reliability and security problems in GitHub Actions workflows.
run_when:
  files_changed:
    - ".github/workflows/**"
runtime:
  image: ghcr.io/adversarylabs/github-actions:0.1.0
  command:
    - /adversary/run
permissions:
  filesystem:
    read:
      - "."
    write:
      - ".adversary/results"
  network: false
  env: []
findings:
  format: adversary.findings.v1
`)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	manifest, err := LoadManifest(path)
	if err != nil {
		t.Fatal(err)
	}

	if manifest.Name != "adversarylabs/github-actions" {
		t.Fatalf("Name = %q", manifest.Name)
	}
	if manifest.Runtime.Image != "ghcr.io/adversarylabs/github-actions:0.1.0" {
		t.Fatalf("Runtime.Image = %q", manifest.Runtime.Image)
	}
	if len(manifest.Runtime.Command) != 1 || manifest.Runtime.Command[0] != "/adversary/run" {
		t.Fatalf("Runtime.Command = %#v", manifest.Runtime.Command)
	}
	if manifest.Permissions.Network == nil || *manifest.Permissions.Network {
		t.Fatalf("Permissions.Network = %#v", manifest.Permissions.Network)
	}
	if got := manifest.RunWhen.FilesChanged[0]; got != ".github/workflows/**" {
		t.Fatalf("RunWhen.FilesChanged[0] = %q", got)
	}
}

func TestResolveReferenceLocalDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "adversary.yaml"), []byte(`name: local/adversary
runtime:
  image: example/adversary:latest
`), 0644); err != nil {
		t.Fatal(err)
	}

	resolved, err := ResolveReference(dir)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Name != "local/adversary" {
		t.Fatalf("Name = %q", resolved.Name)
	}
	if resolved.Image != "example/adversary:latest" {
		t.Fatalf("Image = %q", resolved.Image)
	}
	if resolved.Manifest == nil {
		t.Fatal("Manifest is nil")
	}
}

func TestResolveReferenceContainerImage(t *testing.T) {
	resolved, err := ResolveReference("ghcr.io/adversarylabs/dockerfile:0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Name != "ghcr.io/adversarylabs/dockerfile:0.1.0" {
		t.Fatalf("Name = %q", resolved.Name)
	}
	if resolved.Image != "ghcr.io/adversarylabs/dockerfile:0.1.0" {
		t.Fatalf("Image = %q", resolved.Image)
	}
	if resolved.Manifest != nil {
		t.Fatal("Manifest is not nil")
	}
}
