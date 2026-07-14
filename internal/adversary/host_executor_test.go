package adversary

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	semver "github.com/Masterminds/semver/v3"
)

type completedRuntimeProcess struct{}

func (completedRuntimeProcess) PID() int    { return 0 }
func (completedRuntimeProcess) Wait() error { return nil }
func (completedRuntimeProcess) Kill() error { return nil }

type recordingProcessLauncher struct{ options ProcessLaunchOptions }

func (l *recordingProcessLauncher) Start(options ProcessLaunchOptions) (RunningProcess, error) {
	l.options = options
	return completedRuntimeProcess{}, nil
}

type recordingOutputRunner struct {
	options ProcessOutputOptions
	stdout  []byte
}

func (r *recordingOutputRunner) RunOutput(_ context.Context, options ProcessOutputOptions) ([]byte, []byte, error) {
	r.options = options
	return append([]byte(nil), r.stdout...), nil, nil
}

func TestHostExecutorRejectsNetworkRestriction(t *testing.T) {
	result, err := (HostExecutor{}).Run(context.Background(), RuntimeSpec{NetworkDisabled: true, Command: []string{"true"}})
	if err == nil || !strings.Contains(err.Error(), "cannot enforce disabled network") {
		t.Fatalf("result = %#v, error = %v", result, err)
	}
	var unsupported *UnsupportedFeatureError
	if !errors.As(err, &unsupported) {
		t.Fatalf("error type = %T", err)
	}
}

func TestHostExecutorRejectsImageRuntime(t *testing.T) {
	_, err := (HostExecutor{}).Run(context.Background(), RuntimeSpec{Image: "node:22", Command: []string{"node"}})
	var unsupported *UnsupportedFeatureError
	if !errors.As(err, &unsupported) || unsupported.Feature != "container image runtime execution" {
		t.Fatalf("error = %v", err)
	}
}

func TestHostExecutorArgsUseCommandAndEnvironment(t *testing.T) {
	args := []string{"node", "/tmp/adversary/dist/index.js"}
	spec := RuntimeSpec{
		Command:       args,
		AdversaryPath: "/tmp/adversary",
		Env: map[string]string{
			"ADVERSARY_REPO": "/repo",
		},
	}
	if len(spec.Command) != 2 || spec.Command[0] != "node" {
		t.Fatalf("unexpected host command: %#v", spec.Command)
	}
}

func TestHostExecutorResolvesNamedProcessFromCapturedEnvironment(t *testing.T) {
	captured, hostile := t.TempDir(), t.TempDir()
	environment := NewProcessEnvironment([]string{"PATH=" + captured, "MARKER=captured"}, false)
	t.Setenv("PATH", hostile)
	launcher := &recordingProcessLauncher{}
	resolved := filepath.Join(captured, "scanner")
	executor := HostExecutor{
		Environment: environment,
		ResolveExecutable: func(name string) (string, error) {
			if name != "scanner" {
				t.Fatalf("resolver input = %q", name)
			}
			return resolved, nil
		},
		Launcher: launcher,
	}
	if _, err := executor.Run(context.Background(), RuntimeSpec{RuntimeName: "process", Command: []string{"scanner", "--check"}, AdversaryPath: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	if launcher.options.Path != resolved || len(launcher.options.Args) != 1 || launcher.options.Args[0] != "--check" {
		t.Fatalf("launch options = %#v", launcher.options)
	}
	joined := strings.Join(launcher.options.Env, "\n")
	if !strings.Contains(joined, "PATH="+captured) || strings.Contains(joined, hostile) || !strings.Contains(joined, "MARKER=captured") {
		t.Fatalf("launch environment = %#v", launcher.options.Env)
	}
}

func TestNodeVersionProbeUsesCapturedEnvironment(t *testing.T) {
	captured, hostile := t.TempDir(), t.TempDir()
	node := filepath.Join(captured, "node")
	environment := NewProcessEnvironment([]string{"PATH=" + hostile, "PATH=" + captured, "NODE_PROBE=captured"}, false)
	t.Setenv("PATH", hostile)
	output := &recordingOutputRunner{stdout: []byte("v22.4.0\n")}
	resolver := NodeResolver{
		LookupEnv: environment.Lookup,
		LookPath: func(name string) (string, error) {
			if name != "node" {
				t.Fatalf("lookup = %q", name)
			}
			return node, nil
		},
		HomeDir:           t.TempDir(),
		Glob:              func(string) ([]string, error) { return nil, nil },
		ResolveExecutable: func(path string) (string, error) { return path, nil },
		Environment:       environment,
		Output:            output,
	}
	got, err := resolver.Find(context.Background(), "22")
	if err != nil || got != node {
		t.Fatalf("Find = %q, %v", got, err)
	}
	if output.options.Path != node || !reflect.DeepEqual(output.options.Args, []string{"--version"}) {
		t.Fatalf("probe options = %#v", output.options)
	}
	joined := strings.Join(output.options.Env, "\n")
	if !strings.Contains(joined, "PATH="+captured) || strings.Contains(joined, "PATH="+hostile) || !strings.Contains(joined, "NODE_PROBE=captured") {
		t.Fatalf("probe environment = %#v", output.options.Env)
	}
}

func TestNodeResolverFailsClosedOnUnsafeCapturedPATH(t *testing.T) {
	environment := NewProcessEnvironment([]string{"PATH=relative"}, false)
	resolver := NodeResolver{
		LookupEnv: environment.Lookup,
		LookPath: func(name string) (string, error) {
			return environment.LookPath(name, func(candidate string) (string, error) { return candidate, nil })
		},
		HomeDir: t.TempDir(),
		Glob: func(string) ([]string, error) {
			t.Fatal("unsafe PATH fell through to conventional runtime discovery")
			return nil, nil
		},
		ResolveExecutable: func(path string) (string, error) { return path, nil },
		Environment:       environment,
		Output:            &recordingOutputRunner{stdout: []byte("v22.4.0\n")},
	}
	if _, err := resolver.Find(context.Background(), "22"); !errors.Is(err, ErrUnsafeCapturedPATH) {
		t.Fatalf("error = %v", err)
	}
}

func TestFindNodeDoesNotClaimUnmanagedRuntimeDirectory(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("ADVERSARY_DATA_DIR", dataDir)
	t.Setenv("PATH", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	nodePath := filepath.Join(dataDir, "runtimes", "node", "22", runtime.GOOS+"-"+runtime.GOARCH, "bin", "node")
	if err := os.MkdirAll(filepath.Dir(nodePath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nodePath, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}

	if got, err := findNode("22"); err == nil || got != "" {
		t.Fatalf("findNode used undocumented runtime: %q, %v", got, err)
	}
}

func TestFindNodeUsesExplicitOverride(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	nodePath := filepath.Join(root, "node")
	if err := os.WriteFile(nodePath, []byte("#!/bin/sh\nprintf 'v22.3.0\\n'\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ADVERSARY_NODE_PATH", nodePath)

	got, err := findNode("22")
	if err != nil {
		t.Fatal(err)
	}
	if got != nodePath {
		t.Fatalf("node path = %q, want %q", got, nodePath)
	}
}

func TestFindNodeRejectsInvalidOverride(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	nodePath := filepath.Join(root, "node")
	if err := os.WriteFile(nodePath, []byte("#!/bin/sh\nprintf v21.9.0\\n"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ADVERSARY_NODE_PATH", nodePath)
	if _, err := findNode("22"); err == nil || !strings.Contains(err.Error(), "not executable") {
		t.Fatalf("error = %v", err)
	}
}

func TestNodeConstraintRanges(t *testing.T) {
	for _, tc := range []struct {
		requirement, version string
		want                 bool
	}{{"22", "22.9.1", true}, {"22", "23.0.0", false}, {">=20, <23", "22.1.0", true}} {
		c, err := nodeConstraint(tc.requirement)
		if err != nil {
			t.Fatal(err)
		}
		v, _ := semver.NewVersion(tc.version)
		if got := c.Check(v); got != tc.want {
			t.Fatalf("%q against %s = %v", tc.requirement, tc.version, got)
		}
	}
}

func TestPrintExecutionSummaryLabelsHostProcess(t *testing.T) {
	var out bytes.Buffer
	printExecutionSummary(&out, RuntimeResult{ExitCode: 0, Kind: "Process"}, 0, time.Millisecond, time.Millisecond)
	if !strings.Contains(out.String(), "Process exit code: 0") {
		t.Fatalf("summary = %q", out.String())
	}
}
