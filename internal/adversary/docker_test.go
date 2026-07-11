package adversary

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	semver "github.com/Masterminds/semver/v3"
)

func TestHostExecutorRejectsNetworkRestriction(t *testing.T) {
	result, err := (HostExecutor{}).Run(context.Background(), ContainerSpec{NetworkDisabled: true, Command: []string{"true"}})
	if err == nil || !strings.Contains(err.Error(), "cannot enforce disabled network") {
		t.Fatalf("result = %#v, error = %v", result, err)
	}
	var unsupported *UnsupportedFeatureError
	if !errors.As(err, &unsupported) {
		t.Fatalf("error type = %T", err)
	}
}

func TestHostExecutorRejectsImageRuntime(t *testing.T) {
	_, err := (HostExecutor{}).Run(context.Background(), ContainerSpec{Image: "node:22", Command: []string{"node"}})
	var unsupported *UnsupportedFeatureError
	if !errors.As(err, &unsupported) || unsupported.Feature != "container image runtime execution" {
		t.Fatalf("error = %v", err)
	}
}

func TestHostExecutorArgsUseCommandAndEnvironment(t *testing.T) {
	args := []string{"node", "/tmp/adversary/dist/index.js"}
	spec := ContainerSpec{
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
	printExecutionSummary(&out, ContainerResult{ExitCode: 0, Kind: "Process"}, 0, time.Millisecond, time.Millisecond)
	if !strings.Contains(out.String(), "Process exit code: 0") {
		t.Fatalf("summary = %q", out.String())
	}
}
