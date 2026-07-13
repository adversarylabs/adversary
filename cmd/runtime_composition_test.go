package cmd

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	internaladversary "github.com/adversarylabs/adversary/internal/adversary"
	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/pkg/pack"
)

type compositionProcess struct{}

func (compositionProcess) PID() int    { return 0 }
func (compositionProcess) Wait() error { return nil }

func TestNewProcessAppCapturesBuildStateBeforeEnvironmentMutation(t *testing.T) {
	capturedHome := t.TempDir()
	t.Setenv("HOME", capturedHome)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(capturedHome, "captured-cache"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(capturedHome, "captured-config"))
	t.Setenv("ADVERSARY_DATA_DIR", filepath.Join(capturedHome, "captured-data"))
	want, err := pack.ResolveBuildStateDir("")
	if err != nil {
		t.Fatal(err)
	}
	app, err := newProcessApp(&bytes.Buffer{}, &bytes.Buffer{}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", filepath.Join(t.TempDir(), "poisoned-cache"))
	deps := app.Dependencies()
	projects, ok := deps.Projects.(processProjects)
	if !ok {
		t.Fatalf("projects=%T", deps.Projects)
	}
	runtimeService, ok := deps.Runtime.(processRuntime)
	if !ok {
		t.Fatalf("runtime=%T", deps.Runtime)
	}
	if projects.buildStateDir != want || runtimeService.buildStateDir != want {
		t.Fatalf("build state projects=%q runtime=%q want=%q", projects.buildStateDir, runtimeService.buildStateDir, want)
	}
}
func (compositionProcess) Kill() error { return nil }

type compositionLauncher struct {
	options internaladversary.ProcessLaunchOptions
}

type compositionGit struct{}

func (compositionGit) ChangedFiles(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}

type compositionOutput struct {
	options internaladversary.ProcessOutputOptions
}

func (o *compositionOutput) RunOutput(_ context.Context, options internaladversary.ProcessOutputOptions) ([]byte, []byte, error) {
	o.options = options
	return nil, nil, nil
}

func (l *compositionLauncher) Start(options internaladversary.ProcessLaunchOptions) (internaladversary.RunningProcess, error) {
	l.options = options
	_, _ = io.WriteString(options.Stdout, "child stdout\n")
	_, _ = io.WriteString(options.Stderr, "child stderr\n")
	return compositionProcess{}, nil
}

func TestProcessRuntimeRoutesDistinctStreamsAndSnapshot(t *testing.T) {
	stdin, stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}, &bytes.Buffer{}
	bin := t.TempDir()
	executable := filepath.Join(bin, "tool")
	env := internaladversary.NewProcessEnvironment([]string{"PATH=" + bin, "ADVERSARY_REPO=hostile"}, false)
	files := internaladversary.OSRuntimeFiles{}
	now := func() time.Time { return time.Unix(42, 0) }
	launcher := &compositionLauncher{}
	resolve := func(string) (string, error) { return executable, nil }
	p := processRuntime{stdin: stdin, environment: env, resolveExecutable: resolve, launcher: launcher, git: compositionGit{}, tempDir: "/captured/tmp", homeDir: "/captured/home", dataRoot: "/captured/data", buildStateDir: "/captured/build-state", now: now, files: files, node: internaladversary.NodeResolver{LookPath: resolve}, buildProject: func(context.Context, pack.BuildOptions) error { return nil }}
	runner := p.runner(application.AdversaryRunOptions{Stdout: stdout, Stderr: stderr})
	executor, ok := runner.Executor.(internaladversary.HostExecutor)
	if !ok {
		t.Fatalf("executor = %T", runner.Executor)
	}
	if runner.Stdout != stdout || executor.Stdin != stdin || executor.Stdout != stderr || executor.Stderr != stderr {
		t.Fatal("structured output and child diagnostics were not routed independently")
	}
	if runner.TempDir != "/captured/tmp" || runner.HomeDir != "/captured/home" || runner.DataRoot != "/captured/data" || runner.BuildStateDir != "/captured/build-state" || runner.Files == nil || runner.BuildProject == nil || runner.Shell == nil || runner.Git == nil || runner.Now().Unix() != 42 {
		t.Fatal("runtime dependencies were not retained by the composed runner")
	}
	if shell, err := executor.Shell(); err != nil || len(shell) != 1 || shell[0] != executable {
		t.Fatalf("shell = %#v, %v", shell, err)
	}
	entries := executor.Environment.Entries(map[string]string{"ADVERSARY_REPO": "owned"})
	if len(entries) != 2 || entries[0] != "ADVERSARY_REPO=owned" || entries[1] != "PATH="+bin {
		t.Fatalf("merged environment = %#v", entries)
	}
	if _, err := executor.Run(context.Background(), internaladversary.ContainerSpec{RuntimeName: "process", Command: []string{"tool"}, AdversaryPath: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("child process polluted structured stdout: %q", stdout.String())
	}
	if got := stderr.String(); got != "child stdout\nchild stderr\n" {
		t.Fatalf("child diagnostics = %q", got)
	}
	if launcher.options.Path != executable || launcher.options.Stdout != stderr || launcher.options.Stderr != stderr {
		t.Fatalf("launch options = %#v", launcher.options)
	}
}

func TestApplicationDataRootIncludesRetiredSiblingStores(t *testing.T) {
	data := filepath.Join("captured", "data")
	repository := filepath.Join(data, "repository-v1")
	if got := applicationDataRoot(repository); got != data {
		t.Fatalf("application data root = %q, want %q", got, data)
	}
	retired := filepath.Join(data, "materialized", "artifact")
	relative, err := filepath.Rel(applicationDataRoot(repository), retired)
	if err != nil || relative == ".." || filepath.IsAbs(relative) {
		t.Fatalf("retired sibling escaped trust boundary: relative=%q err=%v", relative, err)
	}
}

func TestBrowserLauncherUsesCapturedCanonicalProcessState(t *testing.T) {
	captured, live := t.TempDir(), t.TempDir()
	environment := internaladversary.NewProcessEnvironment([]string{"PATH=" + captured, "BROWSER_MARKER=captured"}, false)
	t.Setenv("PATH", live)
	executable := filepath.Join(captured, "browser")
	output := &compositionOutput{}
	if err := openBrowser(context.Background(), "https://example.test/login", environment, func(string) (string, error) {
		return executable, nil
	}, output); err != nil {
		t.Fatal(err)
	}
	if output.options.Path != executable || len(output.options.Args) == 0 || output.options.Args[len(output.options.Args)-1] != "https://example.test/login" {
		t.Fatalf("browser options = %#v", output.options)
	}
	joined := strings.Join(output.options.Env, "\n")
	if !strings.Contains(joined, "PATH="+captured) || strings.Contains(joined, live) || !strings.Contains(joined, "BROWSER_MARKER=captured") {
		t.Fatalf("browser environment = %#v", output.options.Env)
	}
}

func TestPATHExecutableResolverReturnsCanonicalTargetWhileExplicitResolverRejectsAlias(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unprivileged Windows symlink creation is not portable")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "tool-real")
	if err := os.WriteFile(target, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "tool")
	if err := os.Symlink(target, alias); err != nil {
		t.Fatal(err)
	}
	strict, fromPATH := executableResolvers(internaladversary.OSRuntimeFiles{}, "")
	got, err := fromPATH(alias)
	if err != nil || got != target {
		t.Fatalf("PATH resolver = %q, %v; want canonical target %q", got, err, target)
	}
	if _, err := strict(alias); err == nil || !strings.Contains(err.Error(), "symlink component") {
		t.Fatalf("explicit resolver accepted alias: %v", err)
	}
	other := filepath.Join(root, "tool-other")
	if err := os.WriteFile(other, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, alias); err != nil {
		t.Fatal(err)
	}
	if got != target {
		t.Fatalf("resolved executable changed after alias swap: %q", got)
	}
}
