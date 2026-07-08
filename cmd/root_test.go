package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitCommandGeneratesTypeScriptProject(t *testing.T) {
	dir := t.TempDir()
	destination := filepath.Join(dir, "hello-world")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := NewRootCommand(&stdout, &stderr)
	cmd.SetArgs([]string{"init", destination, "--sdk", "typescript"})

	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}

	for _, rel := range []string{
		"adversary.yaml",
		"Dockerfile",
		"package.json",
		"tsconfig.json",
		"README.md",
		"AGENTS.md",
		".gitignore",
		"dist/index.js",
		"dist/index.d.ts",
		"src/index.ts",
		"test/index.test.ts",
		"fixtures/clean/README.md",
		"fixtures/vulnerable/.gitkeep",
		"vendor/adversary-sdk/dist/index.js",
	} {
		if _, err := os.Stat(filepath.Join(destination, rel)); err != nil {
			t.Fatalf("expected generated file %s: %v", rel, err)
		}
	}

	distPath := filepath.Join(destination, "dist/index.js")
	if err := os.WriteFile(distPath, []byte("// overwritten by build\n"), 0644); err != nil {
		t.Fatalf("generated dist file should be writable: %v", err)
	}

	manifest := readFile(t, filepath.Join(destination, "adversary.yaml"))
	if !strings.Contains(manifest, "name: local/hello-world") {
		t.Fatalf("manifest did not substitute name:\n%s", manifest)
	}
	if !strings.Contains(manifest, "manual: true") {
		t.Fatalf("manifest missing manual trigger:\n%s", manifest)
	}
	if strings.Contains(manifest, "files_changed") {
		t.Fatalf("manifest should not include files_changed:\n%s", manifest)
	}

	agents := readFile(t, filepath.Join(destination, "AGENTS.md"))
	for _, want := range []string{
		"This repository contains an Adversary Labs adversary.",
		"Parse files once whenever practical.",
		"Include evidence with every finding.",
		"Never modify the scanned repository.",
	} {
		if !strings.Contains(agents, want) {
			t.Fatalf("AGENTS.md missing %q in:\n%s", want, agents)
		}
	}

	output := stdout.String()
	for _, want := range []string{
		"✓ Generated project",
		"SDK",
		"TypeScript",
		"npm install",
		"npm run build",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("init output missing %q in:\n%s", want, output)
		}
	}
}

func TestInitCommandRejectsUnsupportedSDK(t *testing.T) {
	dir := t.TempDir()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := NewRootCommand(&stdout, &stderr)
	cmd.SetArgs([]string{"init", filepath.Join(dir, "hello-world"), "--sdk", "python"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), `unsupported SDK "python"; supported SDKs: typescript`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInitCommandRejectsExistingDestination(t *testing.T) {
	dir := t.TempDir()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := NewRootCommand(&stdout, &stderr)
	cmd.SetArgs([]string{"init", dir})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "destination already exists") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
