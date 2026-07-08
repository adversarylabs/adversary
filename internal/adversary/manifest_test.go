package adversary

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadManifest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "adversary.yaml")
	data := []byte(`name: adversarylabs/github-actions
version: 0.1.0
description: Finds reliability and security problems in GitHub Actions workflows.
triggers:
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
	if got := manifest.Triggers.FilesChanged[0]; got != ".github/workflows/**" {
		t.Fatalf("Triggers.FilesChanged[0] = %q", got)
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
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM scratch\n"), 0644); err != nil {
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
	if !resolved.LocalDir {
		t.Fatal("LocalDir is false")
	}
	if resolved.BuildContext != dir {
		t.Fatalf("BuildContext = %q", resolved.BuildContext)
	}
	if !resolved.HasDockerfile {
		t.Fatal("HasDockerfile is false")
	}
}

func TestResolveReferenceLocalDirectoryWithoutDockerfile(t *testing.T) {
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
	if !resolved.LocalDir {
		t.Fatal("LocalDir is false")
	}
	if resolved.HasDockerfile {
		t.Fatal("HasDockerfile is true")
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
	if resolved.LocalDir {
		t.Fatal("LocalDir is true")
	}
}

func TestShouldBuildAdversary(t *testing.T) {
	tests := []struct {
		name     string
		resolved ResolvedAdversary
		opts     RunOptions
		want     bool
	}{
		{
			name: "local directory with Dockerfile builds by default",
			resolved: ResolvedAdversary{
				LocalDir:      true,
				HasDockerfile: true,
			},
			want: true,
		},
		{
			name: "no build skips local Dockerfile",
			resolved: ResolvedAdversary{
				LocalDir:      true,
				HasDockerfile: true,
			},
			opts: RunOptions{NoBuild: true},
			want: false,
		},
		{
			name: "local directory without Dockerfile does not build",
			resolved: ResolvedAdversary{
				LocalDir: true,
			},
			opts: RunOptions{Build: true},
			want: false,
		},
		{
			name: "image ref never builds",
			resolved: ResolvedAdversary{
				HasDockerfile: true,
			},
			opts: RunOptions{Build: true},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ShouldBuildAdversary(tt.resolved, tt.opts)
			if got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRepositoryContents(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "README.md"), "readme\n")
	writeFile(t, filepath.Join(dir, "cmd", "main.go"), "package main\n")
	writeFile(t, filepath.Join(dir, ".git", "HEAD"), "ref\n")

	got, err := RepositoryContents(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"README.md", "cmd/"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("contents = %#v, want %#v", got, want)
	}
}

func TestPrintInspect(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "README.md"), "readme\n")

	var b strings.Builder
	PrintInspect(&b, "./adv", NewRunConfig(ResolvedAdversary{
		Name:          "local/adversary",
		Image:         "example/adversary:latest",
		Command:       []string{"/adversary/run"},
		LocalDir:      true,
		BuildContext:  "./adv",
		HasDockerfile: true,
	}, dir, "/tmp/adversary-run", RunOptions{Verbose: true}))

	got := b.String()
	for _, want := range []string{
		"Adversary",
		"Image",
		"example/adversary:latest",
		"Build context",
		"./adv",
		"Repository contents",
		"README.md",
		"Command",
		"/adversary/run",
		"Environment",
		"ADVERSARY_REPO=/workspace",
		"Docker command",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("inspect output missing %q in:\n%s", want, got)
		}
	}
}

type fakeGitDiffer struct {
	files []string
}

func (f fakeGitDiffer) ChangedFiles(ctx context.Context, repoPath, baseRef, headRef string) ([]string, error) {
	return f.files, nil
}

type recordingExecutor struct {
	called bool
	input  Input
}

func (e *recordingExecutor) Run(ctx context.Context, spec ContainerSpec) (ContainerResult, error) {
	e.called = true

	data, err := os.ReadFile(filepath.Join(spec.RunDir, "input.json"))
	if err != nil {
		return ContainerResult{}, err
	}
	if err := json.Unmarshal(data, &e.input); err != nil {
		return ContainerResult{}, err
	}

	output := `{"schema_version":"adversary.findings.v1","findings":[]}`
	if err := os.WriteFile(filepath.Join(spec.RunDir, "output.json"), []byte(output), 0644); err != nil {
		return ContainerResult{}, err
	}
	return ContainerResult{ExitCode: 0}, nil
}

func TestRunSkipsWhenChangedFilesDoNotMatchTriggers(t *testing.T) {
	adversaryDir := t.TempDir()
	writeFile(t, filepath.Join(adversaryDir, "adversary.yaml"), `name: local/adversary
triggers:
  files_changed:
    - "Dockerfile"
runtime:
  image: local/adversary:0.1.0
  command:
    - /adversary/run
`)

	repoDir := t.TempDir()
	executor := &recordingExecutor{}
	var stdout strings.Builder

	err := Runner{
		Stdout:   &stdout,
		Stderr:   &strings.Builder{},
		Git:      fakeGitDiffer{files: []string{"README.md"}},
		Executor: executor,
	}.Run(context.Background(), RunOptions{
		AdversaryRef: adversaryDir,
		RepoPath:     repoDir,
		BaseRef:      "main",
		HeadRef:      "HEAD",
	})
	if err != nil {
		t.Fatal(err)
	}
	if executor.called {
		t.Fatal("executor was called")
	}
	if !strings.Contains(stdout.String(), "Skipped local/adversary") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRunAllFilesBypassesTriggerSkipAndMarksInputScanMode(t *testing.T) {
	adversaryDir := t.TempDir()
	writeFile(t, filepath.Join(adversaryDir, "adversary.yaml"), `name: local/adversary
triggers:
  files_changed:
    - "Dockerfile"
runtime:
  image: local/adversary:0.1.0
  command:
    - /adversary/run
`)

	repoDir := t.TempDir()
	executor := &recordingExecutor{}

	err := Runner{
		Stdout:   &strings.Builder{},
		Stderr:   &strings.Builder{},
		Git:      fakeGitDiffer{files: []string{"README.md"}},
		Executor: executor,
	}.Run(context.Background(), RunOptions{
		AdversaryRef: adversaryDir,
		RepoPath:     repoDir,
		BaseRef:      "main",
		HeadRef:      "HEAD",
		AllFiles:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !executor.called {
		t.Fatal("executor was not called")
	}
	if executor.input.Change == nil {
		t.Fatal("input.Change is nil")
	}
	if executor.input.Change.ScanMode != "all" {
		t.Fatalf("ScanMode = %q", executor.input.Change.ScanMode)
	}
	if len(executor.input.Change.ChangedFiles) != 1 || executor.input.Change.ChangedFiles[0] != "README.md" {
		t.Fatalf("ChangedFiles = %#v", executor.input.Change.ChangedFiles)
	}
}
