package adversary

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/adversarylabs/adversary/pkg/detection"
	"github.com/adversarylabs/adversary/pkg/pack"
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
  name: node
  version: "22"
  command:
    - dist/index.js
permissions:
  filesystem:
    read:
      - "."
    write:
      - ".adversary/results"
  network: false
  environment:
    allow: []
findings:
  format: adversary.review.v1
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
	if manifest.Runtime.Name != "node" || manifest.Runtime.Version != "22" {
		t.Fatalf("Runtime = %#v", manifest.Runtime)
	}
	if strings.Join(manifest.Runtime.Command, " ") != "dist/index.js" {
		t.Fatalf("Runtime.Command = %#v", manifest.Runtime.Command)
	}
	if manifest.Permissions.Network == nil || *manifest.Permissions.Network {
		t.Fatalf("Permissions.Network = %#v", manifest.Permissions.Network)
	}
	if got := manifest.Triggers.FilesChanged[0]; got != ".github/workflows/**" {
		t.Fatalf("Triggers.FilesChanged[0] = %q", got)
	}
}

func TestRuntimeExecutionImageNeverChoosesBetweenAmbiguousIdentities(t *testing.T) {
	for name, runtime := range map[string]Runtime{
		"both":    {Name: "node", Image: "node:22"},
		"neither": {},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := runtimeExecutionImage(runtime); err == nil {
				t.Fatal("runtimeExecutionImage accepted ambiguous identity")
			}
		})
	}
	if got, err := runtimeExecutionImage(Runtime{Name: "node"}); err != nil || got != "host:node" {
		t.Fatalf("named runtime image=%q err=%v", got, err)
	}
	if got, err := runtimeExecutionImage(Runtime{Image: "node:22"}); err != nil || got != "node:22" {
		t.Fatalf("OCI runtime image=%q err=%v", got, err)
	}
}

func TestResolveReferenceLocalDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "adversary.yaml"), []byte(`name: local/adversary
runtime:
  name: node
  version: "22"
  command:
    - dist/index.js
`), 0644); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "package.json"), `{"type":"module"}`)
	writeFile(t, filepath.Join(dir, "dist", "index.js"), "console.log('ok')\n")

	resolved, err := ResolveReference(dir)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Name != "local/adversary" {
		t.Fatalf("Name = %q", resolved.Name)
	}
	if resolved.Image != "host:node" {
		t.Fatalf("Image = %q", resolved.Image)
	}
	if resolved.RuntimeName != "node" || resolved.RuntimeVersion != "22" {
		t.Fatalf("Runtime = %s@%s", resolved.RuntimeName, resolved.RuntimeVersion)
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
	if resolved.ExecutionPath != dir {
		t.Fatalf("ExecutionPath = %q", resolved.ExecutionPath)
	}
}

func TestResolveReferenceDoesNotInferNodeFromProjectFiles(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "adversary.yaml"), `name: local/process
runtime:
  name: process
  version: "1"
  command: [tool]
`)
	writeFile(t, filepath.Join(dir, "package.json"), `{}`)
	writeFile(t, filepath.Join(dir, "dist", "index.js"), `ignored`)
	resolved, err := ResolveReference(dir)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.RuntimeName != "process" || strings.Join(resolved.Command, " ") != "tool" {
		t.Fatalf("inferred runtime: %#v", resolved)
	}
}

func TestResolveReferenceUnknownRemoteRefDoesNotBecomeExecutableImage(t *testing.T) {
	t.Setenv("ADVERSARY_DATA_DIR", t.TempDir())
	resolved, err := ResolveReference("ghcr.io/adversarylabs/dockerfile:0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Name != "ghcr.io/adversarylabs/dockerfile:0.1.0" {
		t.Fatalf("Name = %q", resolved.Name)
	}
	if resolved.Image != "" {
		t.Fatalf("Image = %q", resolved.Image)
	}
	if resolved.Manifest != nil {
		t.Fatal("Manifest is not nil")
	}
	if resolved.LocalDir {
		t.Fatal("LocalDir is true")
	}
}

func TestResolveReferenceUnifiedRepositoryByNameTagAndDigest(t *testing.T) {
	dataDir := t.TempDir()
	t.Cleanup(func() { makeManifestTestTreeWritable(dataDir) })
	t.Setenv("ADVERSARY_DATA_DIR", dataDir)
	project := t.TempDir()
	writeFile(t, filepath.Join(project, "adversary.yaml"), `name: local/dockerfile-adversary
version: 0.1.0
runtime:
  name: node
  version: "22"
  command:
    - dist/index.js
permissions:
  network: false
`)
	writeFile(t, filepath.Join(project, "package.json"), `{"type":"module"}`)
	writeFile(t, filepath.Join(project, "dist", "index.js"), "console.log('ok')\n")
	artifact, err := pack.Create(context.Background(), pack.Options{Dir: project})
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := DefaultResolver()
	if err != nil {
		t.Fatal(err)
	}
	record, err := resolver.ImportPacked(artifact, "local/dockerfile-adversary:0.1.0")
	if err != nil {
		t.Fatal(err)
	}

	for _, ref := range []string{"local/dockerfile-adversary:0.1.0", record.Digest} {
		resolved, err := ResolveReference(ref)
		if err != nil {
			t.Fatalf("resolve %q: %v", ref, err)
		}
		if resolved.Name != "local/dockerfile-adversary" {
			t.Fatalf("resolve %q name = %q", ref, resolved.Name)
		}
		if resolved.Image != "host:node" {
			t.Fatalf("resolve %q image = %q", ref, resolved.Image)
		}
		if resolved.RuntimeName != "node" || resolved.RuntimeVersion != "22" {
			t.Fatalf("resolve %q runtime = %s@%s", ref, resolved.RuntimeName, resolved.RuntimeVersion)
		}
		wantCommand := []string{"node", filepath.Join(resolved.ExecutionPath, "dist", "index.js")}
		if strings.Join(resolved.Command, "\x00") != strings.Join(wantCommand, "\x00") {
			t.Fatalf("resolve %q command = %#v, want %#v", ref, resolved.Command, wantCommand)
		}
		if !resolved.LocalDir {
			t.Fatalf("resolve %q did not materialize local dir", ref)
		}
		if !resolved.StoreBacked {
			t.Fatalf("resolve %q did not mark store-backed", ref)
		}
		if _, err := os.Stat(filepath.Join(resolved.BuildContext, "adversary.yaml")); err != nil {
			t.Fatalf("materialized adversary.yaml missing: %v", err)
		}
	}
}

func makeManifestTestTreeWritable(root string) {
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err == nil {
			_ = os.Chmod(path, info.Mode().Perm()|0700)
		}
		return nil
	})
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
		Image:         "adversary-local-typescript",
		Command:       []string{"node", "/tmp/adversary/dist/index.js"},
		LocalDir:      true,
		BuildContext:  "./adv",
		ExecutionPath: "./adv",
	}, dir, "/tmp/adversary-run", RunOptions{Verbose: true}))

	got := b.String()
	for _, want := range []string{
		"Adversary",
		"Runtime",
		"adversary-local-typescript",
		"Project",
		"./adv",
		"Repository contents",
		"README.md",
		"Command",
		"node",
		"/tmp/adversary/dist/index.js",
		"Environment",
		"ADVERSARY_REPO=" + dir,
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
	called  bool
	input   Input
	spec    RuntimeSpec
	context detection.Context
}

func (*recordingExecutor) Backend() ExecutorBackend           { return NativeSandboxExecutorBackend }
func (*recordingExecutor) Capabilities() ExecutorCapabilities { return allTestExecutorCapabilities() }

func allTestExecutorCapabilities() ExecutorCapabilities {
	return ExecutorCapabilities{
		FilesystemReadIsolation:  true,
		FilesystemWriteIsolation: true,
		EnvironmentIsolation:     true,
		NetworkIsolation:         true,
		CPULimits:                true,
		MemoryLimits:             true,
		ProcessLimits:            true,
	}
}

func (e *recordingExecutor) Run(ctx context.Context, spec RuntimeSpec) (RuntimeResult, error) {
	e.called = true
	e.spec = spec

	data, err := os.ReadFile(filepath.Join(spec.RunDir, "input.json"))
	if err != nil {
		return RuntimeResult{}, err
	}
	if err := json.Unmarshal(data, &e.input); err != nil {
		return RuntimeResult{}, err
	}
	if path := spec.Env["ADVERSARY_CHANGE_CONTEXT"]; path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return RuntimeResult{}, err
		}
		if err := json.Unmarshal(data, &e.context); err != nil {
			return RuntimeResult{}, err
		}
	}

	output := `{"protocolVersion":1,"result":{"adversary":{"name":"local/adversary"},"target":{},"positives":[],"observations":[],"findings":[],"suppressed":{"observations":0,"findings":0}}}`
	if err := os.WriteFile(filepath.Join(spec.RunDir, "output.json"), []byte(output), 0644); err != nil {
		return RuntimeResult{}, err
	}
	return RuntimeResult{ExitCode: 0}, nil
}

type failingGitDiffer struct{}

func (failingGitDiffer) ChangedFiles(context.Context, string, string, string) ([]string, error) {
	return nil, errors.New("Git must not be recalculated")
}

func TestRunUsesPreResolvedReviewContextWithoutRecalculatingGit(t *testing.T) {
	adversaryDir := t.TempDir()
	writeFile(t, filepath.Join(adversaryDir, "adversary.yaml"), `name: local/adversary
runtime:
  name: node
  version: "22"
  command: [dist/index.js]
`)
	writeFile(t, filepath.Join(adversaryDir, "dist", "index.js"), "")
	executor := &recordingExecutor{}
	resolved := &detection.Context{SchemaVersion: detection.SchemaVersion, RepositoryRoot: "/workspace", Mode: detection.ModeBranchComparison, BaseRef: "main", HeadRef: "HEAD", MergeBase: "abc", ChangedFiles: []detection.ChangedFile{{Path: "Dockerfile", Status: detection.StatusModified}}}
	err := Runner{Stdout: &strings.Builder{}, Stderr: &strings.Builder{}, Git: failingGitDiffer{}, Executor: executor}.Run(context.Background(), RunOptions{AdversaryRef: adversaryDir, RepoPath: t.TempDir(), ReviewContext: resolved})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(executor.context, *resolved) {
		t.Fatalf("executor context = %#v, want %#v", executor.context, *resolved)
	}
	if executor.input.Change == nil || !reflect.DeepEqual(executor.input.Change.ChangedFiles, []string{"Dockerfile"}) {
		t.Fatalf("legacy input did not receive resolved paths: %#v", executor.input)
	}
}

func TestRunBuildsLocalTypeScriptAdversaryBeforeExecution(t *testing.T) {
	adversaryDir := t.TempDir()
	writeFile(t, filepath.Join(adversaryDir, "adversary.yaml"), `name: local/adversary
runtime:
  name: node
  version: "22"
  command:
    - dist/index.js
`)
	writeFile(t, filepath.Join(adversaryDir, "package.json"), `{"scripts":{"build":"build"}}`)
	if err := os.MkdirAll(filepath.Join(adversaryDir, "node_modules"), 0755); err != nil {
		t.Fatal(err)
	}
	sdkFixture := `export const DEFAULT_INPUT_PATH = "/adversary/input.json";
export const DEFAULT_OUTPUT_PATH = "/adversary/output.json";
export class Adversary {
  async run(options = {}) {
    const input = options.input ?? (await parseInput(options.inputPath));
    const repoPath = input.source.path;
  }
}
export async function parseInput(path = DEFAULT_INPUT_PATH) {}
export async function writeOutput(output, path = DEFAULT_OUTPUT_PATH) {}
`
	vendoredSDKPath := filepath.Join(adversaryDir, "vendor", "adversary-sdk", "dist", "index.js")
	nodeModulesSDKPath := filepath.Join(adversaryDir, "node_modules", "@adversary", "sdk", "dist", "index.js")
	writeFile(t, vendoredSDKPath, sdkFixture)
	writeFile(t, nodeModulesSDKPath, sdkFixture)
	binDir := t.TempDir()
	npmPath := filepath.Join(binDir, "npm")
	writeFile(t, npmPath, "#!/bin/sh\n/bin/mkdir -p dist\nprintf 'console.log(\"built\")\\n' > dist/index.js\n")
	if err := os.Chmod(npmPath, 0755); err != nil {
		t.Fatal(err)
	}
	nodePath := filepath.Join(binDir, "node")
	writeFile(t, nodePath, "#!/bin/sh\nprintf 'v22.14.0\\n'\n")
	if err := os.Chmod(nodePath, 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir)
	capturedHome := t.TempDir()
	t.Setenv("HOME", capturedHome)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(capturedHome, "captured-cache"))
	buildStateDir, err := pack.ResolveBuildStateDir("")
	if err != nil {
		t.Fatal(err)
	}
	poisonedCache := filepath.Join(t.TempDir(), "poisoned-cache")
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", poisonedCache)

	executor := &recordingExecutor{}
	buildProject := func(ctx context.Context, opts pack.BuildOptions) error {
		if opts.BuildStateDir != buildStateDir {
			t.Fatalf("build state=%q want=%q", opts.BuildStateDir, buildStateDir)
		}
		environment := pack.BuildEnvironment{
			NPM:         npmPath,
			Node:        nodePath,
			Environment: []string{"PATH=" + binDir, "HOME=" + t.TempDir()},
			Run: func(ctx context.Context, executable string, args []string, dir string, env []string, stdout, stderr io.Writer, capture bool) ([]byte, error) {
				cmd := exec.CommandContext(ctx, executable, args...)
				cmd.Dir, cmd.Env, cmd.Stdout, cmd.Stderr = dir, env, stdout, stderr
				if capture {
					return cmd.Output()
				}
				return nil, cmd.Run()
			},
		}
		return pack.BuildProjectWithEnvironment(ctx, opts, environment)
	}
	err = Runner{
		Stdout:        &strings.Builder{},
		Stderr:        &strings.Builder{},
		Executor:      executor,
		BuildProject:  buildProject,
		BuildStateDir: buildStateDir,
	}.Run(context.Background(), RunOptions{
		AdversaryRef: adversaryDir,
		RepoPath:     t.TempDir(),
		Build:        true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !executor.called {
		t.Fatal("executor was not called")
	}
	if _, err := os.Stat(filepath.Join(poisonedCache, "adversary", "build-state")); !os.IsNotExist(err) {
		t.Fatalf("mutated cache used for run build: %v", err)
	}
	builtPath := filepath.Join(adversaryDir, "dist", "index.js")
	if _, err := os.Stat(builtPath); err != nil {
		t.Fatalf("expected local build output: %v", err)
	}
	if len(executor.spec.Command) < 2 || executor.spec.Command[1] != builtPath {
		t.Fatalf("command = %#v, want built entrypoint %q", executor.spec.Command, builtPath)
	}
	for _, path := range []string{vendoredSDKPath, nodeModulesSDKPath} {
		sdkData, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(sdkData) != sdkFixture {
			t.Fatalf("SDK file was modified at %s:\n%s", path, string(sdkData))
		}
	}
}

func TestRunSkipsWhenChangedFilesDoNotMatchTriggers(t *testing.T) {
	adversaryDir := t.TempDir()
	writeFile(t, filepath.Join(adversaryDir, "adversary.yaml"), `name: local/adversary
triggers:
  files_changed:
    - "Dockerfile"
runtime:
  name: node
  version: "22"
  command:
    - dist/index.js
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
  name: node
  version: "22"
  command:
    - dist/index.js
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

func TestRunDefaultOutputIsConciseReview(t *testing.T) {
	adversaryDir := t.TempDir()
	writeFile(t, filepath.Join(adversaryDir, "adversary.yaml"), `name: local/adversary
runtime:
  name: node
  version: "22"
  command:
    - dist/index.js
`)

	var stdout strings.Builder
	var stderr strings.Builder
	err := Runner{
		Stdout:   &stdout,
		Stderr:   &stderr,
		Executor: &recordingExecutor{},
	}.Run(context.Background(), RunOptions{
		AdversaryRef: adversaryDir,
		RepoPath:     t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stderr.String(), "Running ") || strings.Contains(stderr.String(), "exit code") {
		t.Fatalf("stderr = %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "Review complete") {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if strings.Contains(stdout.String(), "Scan complete") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRunRendersVersionedReviewEnvelopeFromChildProcess(t *testing.T) {
	adversaryDir := t.TempDir()
	writeFile(t, filepath.Join(adversaryDir, "adversary.yaml"), `name: dockerfile
runtime:
  name: node
  version: "22"
  command:
    - dist/index.js
`)
	writeFile(t, filepath.Join(adversaryDir, "dist", "index.js"), `import { writeFileSync } from "node:fs";

const output = {
  protocolVersion: 1,
  result: {
    adversary: { name: "dockerfile" },
    target: { repository: process.env.ADVERSARY_REPO, filesScanned: 1 },
    assessment: { risk: "low", summary: "This is a well-structured multi-stage Node Dockerfile with one low-risk reproducibility concern." },
    positives: [
      { key: "dependency-build-runtime", summary: "Dependency installation, build, and runtime are separated cleanly." }
    ],
    observations: [
      { key: "stage-layout", summary: "The Dockerfile defines deps, builder, and runner stages." }
    ],
    findings: [
      {
        id: "base-image",
        ruleId: "dockerfile.base-image.unpinned-digest",
        title: "Base images are not pinned by digest",
        category: "supply-chain",
        severity: "low",
        confidence: "high",
        summary: "Three stages reference node:22-bookworm-slim by tag rather than digest.",
        whyItMatters: "Container image tags are mutable and can resolve to different image contents over time.",
        impact: "Future builds may consume different base images even when the Dockerfile itself has not changed.",
        evidence: [
          { file: "Dockerfile", line: 3, message: "deps stage", snippet: "FROM node:22-bookworm-slim AS deps", metadata: { image: "node:22-bookworm-slim" } },
          { file: "Dockerfile", line: 11, message: "builder stage", snippet: "FROM node:22-bookworm-slim AS builder" },
          { file: "Dockerfile", line: 20, message: "runner stage", snippet: "FROM node:22-bookworm-slim AS runner" }
        ],
        recommendation: "Pin production base images using image:tag@sha256:<digest> when reproducibility and auditability matter.\n\nUse Renovate or Dependabot to keep pinned digests current.",
        remediation: { estimate: "10-20 minutes", complexity: "small" }
      }
    ],
    opinion: { ship: true, summary: "I would ship this Dockerfile as-is. Digest pinning is the only material improvement identified." },
    suppressed: { observations: 0, findings: 0 }
  }
};

writeFileSync(process.env.ADVERSARY_OUTPUT, JSON.stringify(output, null, 2));
`)
	repoDir := t.TempDir()

	var stdout strings.Builder
	err := Runner{
		Stdout:   &stdout,
		Stderr:   &strings.Builder{},
		Executor: systemHostExecutorForTest(nil, &strings.Builder{}, &strings.Builder{}),
	}.Run(context.Background(), RunOptions{
		AdversaryRef: adversaryDir,
		RepoPath:     repoDir,
	})
	var findings *FindingsError
	if !errors.As(err, &findings) {
		t.Fatalf("expected findings status, got %v", err)
	}
	got := stdout.String()
	for _, want := range []string{
		"Overall assessment",
		"Positive signals",
		"Observations",
		"Overall opinion",
		"Category: supply-chain",
		"Confidence: high",
		"Why it matters",
		"Impact",
		"- Dockerfile:3 - deps stage",
		"  FROM node:22-bookworm-slim AS deps",
		"Estimated remediation",
		"10-20 minutes",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("stdout missing %q in:\n%s", want, got)
		}
	}
	for _, notWant := range []string{`"image"`, "Evidence:", "Recommendation:"} {
		if strings.Contains(got, notWant) {
			t.Fatalf("stdout contains %q in:\n%s", notWant, got)
		}
	}
}

func TestRunJSONPrintsCompleteReviewEnvelope(t *testing.T) {
	adversaryDir := t.TempDir()
	writeFile(t, filepath.Join(adversaryDir, "adversary.yaml"), `name: dockerfile
runtime:
  name: node
  version: "22"
  command:
    - dist/index.js
`)
	writeFile(t, filepath.Join(adversaryDir, "dist", "index.js"), `import { writeFileSync } from "node:fs";

writeFileSync(process.env.ADVERSARY_OUTPUT, JSON.stringify({
  protocolVersion: 1,
  result: {
    adversary: { name: "dockerfile" },
    target: { repository: process.env.ADVERSARY_REPO, filesScanned: 1 },
    assessment: { risk: "low", summary: "Well structured." },
    positives: [{ key: "positive", summary: "Good stage separation." }],
    observations: [],
    findings: [{
      id: "base-image",
      title: "Base image is not pinned by digest",
      category: "supply-chain",
      severity: "low",
      confidence: "high",
      summary: "Base image uses a mutable tag.",
      impact: "Builds may drift.",
      evidence: [{ file: "Dockerfile", line: 3, message: "deps stage", metadata: { image: "node:22-bookworm-slim" } }],
      remediation: { estimate: "10-20 minutes" }
    }],
    opinion: { ship: true, summary: "Ship it." },
    suppressed: { observations: 0, findings: 0 }
  }
}));
`)

	var stdout strings.Builder
	err := Runner{
		Stdout:   &stdout,
		Stderr:   &strings.Builder{},
		Executor: systemHostExecutorForTest(nil, &strings.Builder{}, &strings.Builder{}),
	}.Run(context.Background(), RunOptions{
		AdversaryRef: adversaryDir,
		RepoPath:     t.TempDir(),
		Format:       "json",
	})
	var findings *FindingsError
	if !errors.As(err, &findings) {
		t.Fatalf("expected findings status, got %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(stdout.String()), &got); err != nil {
		t.Fatal(err)
	}
	if got["protocolVersion"].(float64) != 1 {
		t.Fatalf("protocolVersion = %v", got["protocolVersion"])
	}
	result := got["result"].(map[string]any)
	if result["assessment"].(map[string]any)["risk"] != "low" {
		t.Fatalf("assessment = %#v", result["assessment"])
	}
	finding := result["findings"].([]any)[0].(map[string]any)
	evidence := finding["evidence"].([]any)[0].(map[string]any)
	if evidence["metadata"].(map[string]any)["image"] != "node:22-bookworm-slim" {
		t.Fatalf("evidence = %#v", evidence)
	}
}
