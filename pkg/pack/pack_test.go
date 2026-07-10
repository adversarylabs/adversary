package pack

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreateRejectsSymlink(t *testing.T) {
	dir := testProject(t)
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("secret"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "outside-link")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := Create(context.Background(), Options{Dir: dir}); err == nil {
		t.Fatal("pack accepted symlink")
	}
}

func TestCreateRejectsSymlinkSwap(t *testing.T) {
	dir := testProject(t)
	target := filepath.Join(dir, "dist", "index.js")
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("outside-secret"), 0644); err != nil {
		t.Fatal(err)
	}
	beforePackOpen = func(rel string) {
		if rel == "dist/index.js" {
			beforePackOpen = nil
			_ = os.Remove(target)
			_ = os.Symlink(outside, target)
		}
	}
	t.Cleanup(func() { beforePackOpen = nil })
	if _, err := Create(context.Background(), Options{Dir: dir}); err == nil {
		t.Fatal("pack accepted symlink swap")
	}
}

func TestCreateRejectsManifestSymlinkSwap(t *testing.T) {
	dir := testProject(t)
	target := filepath.Join(dir, "adversary.yaml")
	outside := filepath.Join(t.TempDir(), "adversary.yaml")
	if err := os.WriteFile(outside, []byte("name: outside/secret\n"), 0644); err != nil {
		t.Fatal(err)
	}
	beforeManifestRead = func() { beforeManifestRead = nil; _ = os.Remove(target); _ = os.Symlink(outside, target) }
	t.Cleanup(func() { beforeManifestRead = nil })
	if _, err := Create(context.Background(), Options{Dir: dir}); err == nil {
		t.Fatal("pack accepted manifest symlink swap")
	}
}

func TestCreatePreservesExecutableMode(t *testing.T) {
	dir := testProject(t)
	path := filepath.Join(dir, "run.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}
	artifact, err := Create(context.Background(), Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	gz, err := gzip.NewReader(bytes.NewReader(artifact.Layer))
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err != nil {
			t.Fatal(err)
		}
		if h.Name == "run.sh" {
			if h.Mode != 0755 {
				t.Fatalf("mode=%o", h.Mode)
			}
			return
		}
	}
}

func TestCreateIsDeterministic(t *testing.T) {
	dir := testProject(t)
	first, err := Create(context.Background(), Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Create(context.Background(), Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if first.ManifestDigest != second.ManifestDigest {
		t.Fatalf("digest mismatch: %s != %s", first.ManifestDigest, second.ManifestDigest)
	}
	if string(first.Layer) != string(second.Layer) {
		t.Fatal("layer is not deterministic")
	}
}

func TestCreateStoresRuntimeRequirement(t *testing.T) {
	dir := testProject(t)
	artifact, err := Create(context.Background(), Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if artifact.RuntimeName != "node" || artifact.RuntimeVersion != "22" {
		t.Fatalf("runtime requirement = %s@%s", artifact.RuntimeName, artifact.RuntimeVersion)
	}
	if artifact.OCIManifest.Annotations["ai.adversary.runtime.name"] != "node" {
		t.Fatalf("runtime name annotation missing: %#v", artifact.OCIManifest.Annotations)
	}
	if artifact.OCIManifest.Annotations["ai.adversary.runtime.version"] != "22" {
		t.Fatalf("runtime version annotation missing: %#v", artifact.OCIManifest.Annotations)
	}
}

func TestCreateStoresAdversaryManifestOutsideImageLayer(t *testing.T) {
	dir := testProject(t)
	manifestBytes, err := os.ReadFile(filepath.Join(dir, "adversary.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Create(context.Background(), Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if string(artifact.AdversaryManifest) != string(manifestBytes) {
		t.Fatal("adversary manifest bytes were not preserved exactly")
	}
	if artifact.AdversaryManifestDigest == "" {
		t.Fatal("adversary manifest digest missing")
	}
	for _, file := range artifact.Files {
		if file.Path == "adversary.yaml" {
			t.Fatal("adversary.yaml must not be included in the runnable image layer")
		}
	}
}

func TestCreateNameOverride(t *testing.T) {
	dir := testProject(t)
	artifact, err := Create(context.Background(), Options{Dir: dir, NameOverride: "ghcr.io/acme/security-reviewer"})
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Name != "ghcr.io/acme/security-reviewer" {
		t.Fatalf("Name = %q", artifact.Name)
	}
	if artifact.ManifestName != "local/security-reviewer" {
		t.Fatalf("ManifestName = %q", artifact.ManifestName)
	}
}

func TestCreateNameOverrideRejectsTag(t *testing.T) {
	dir := testProject(t)
	_, err := Create(context.Background(), Options{Dir: dir, NameOverride: "ghcr.io/acme/security-reviewer:dev"})
	if err == nil {
		t.Fatal("expected tag rejection")
	}
	if !strings.Contains(err.Error(), "must not include a tag") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDefaultIgnoreRules(t *testing.T) {
	dir := testProject(t)
	writeFile(t, dir, "node_modules/pkg/index.js", "ignored")
	writeFile(t, dir, ".git/config", "ignored")
	writeFile(t, dir, ".env", "ignored")
	writeFile(t, dir, ".env.local", "ignored")
	writeFile(t, dir, ".DS_Store", "ignored")
	writeFile(t, dir, "coverage/out.json", "ignored")
	writeFile(t, dir, "tmp/file", "ignored")
	writeFile(t, dir, ".cache/file", "ignored")
	writeFile(t, dir, "Dockerfile", "ignored")

	artifact, err := Create(context.Background(), Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range artifact.Files {
		switch file.Path {
		case "node_modules/pkg/index.js", ".git/config", ".env", ".env.local", ".DS_Store", "coverage/out.json", "tmp/file", ".cache/file", "Dockerfile":
			t.Fatalf("ignored file included: %s", file.Path)
		}
	}
}

func TestAdversaryIgnore(t *testing.T) {
	dir := testProject(t)
	writeFile(t, dir, ".adversaryignore", "secrets/\n*.log\n")
	writeFile(t, dir, "secrets/token.txt", "ignored")
	writeFile(t, dir, "debug.log", "ignored")

	artifact, err := Create(context.Background(), Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range artifact.Files {
		if file.Path == "secrets/token.txt" || file.Path == "debug.log" {
			t.Fatalf("ignored file included: %s", file.Path)
		}
	}
}

func TestCreateSkipsBuildWhenNPMMissingAndDistExists(t *testing.T) {
	dir := testProject(t)
	if err := os.MkdirAll(filepath.Join(dir, "node_modules"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	var stderr strings.Builder
	artifact, err := Create(context.Background(), Options{Dir: dir, Build: true, Stderr: &stderr})
	if err != nil {
		t.Fatal(err)
	}
	if artifact.ManifestDigest == "" {
		t.Fatal("expected packed artifact")
	}
	if !strings.Contains(stderr.String(), "Skipping build: npm was not found") {
		t.Fatalf("expected npm warning, got %q", stderr.String())
	}
}

func TestCreateRejectsUnsupportedBuilder(t *testing.T) {
	dir := testProject(t)
	if err := os.MkdirAll(filepath.Join(dir, "node_modules"), 0755); err != nil {
		t.Fatal(err)
	}
	_, err := Create(context.Background(), Options{Dir: dir, Build: true, Builder: "spaceship"})
	if err == nil {
		t.Fatal("expected unsupported builder error")
	}
	if !strings.Contains(err.Error(), "unsupported builder") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCreateFailsForMissingManifest(t *testing.T) {
	_, err := Create(context.Background(), Options{Dir: t.TempDir()})
	if err == nil {
		t.Fatal("expected missing manifest error")
	}
}

func TestCreateFailsForInvalidManifest(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "adversary.yaml", "version: 0.1.0\n")
	_, err := Create(context.Background(), Options{Dir: dir})
	if err == nil {
		t.Fatal("expected invalid manifest error")
	}
}

func testProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, dir, "adversary.yaml", `name: local/security-reviewer
version: 0.1.0
runtime:
  name: node
  version: "22"
  command:
    - dist/index.js
permissions:
  network: false
`)
	writeFile(t, dir, "README.md", "# Security Reviewer\n")
	writeFile(t, dir, "LICENSE", "MIT\n")
	writeFile(t, dir, "package.json", `{"scripts":{"build":"tsc -p tsconfig.json"}}`)
	writeFile(t, dir, "dist/index.js", "console.log('ok')\n")
	return dir
}

func writeFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	path := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}
