package adversary

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestHostExecutorRejectsNetworkRestriction(t *testing.T) {
	result, err := (HostExecutor{}).Run(context.Background(), ContainerSpec{NetworkDisabled: true, Command: []string{"true"}})
	if err == nil || !strings.Contains(err.Error(), "cannot enforce disabled network") {
		t.Fatalf("result = %#v, error = %v", result, err)
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

func TestFindNodeUsesManagedRuntime(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("ADVERSARY_DATA_DIR", dataDir)
	nodePath := filepath.Join(dataDir, "runtimes", "node", "22", runtime.GOOS+"-"+runtime.GOARCH, "bin", "node")
	if err := os.MkdirAll(filepath.Dir(nodePath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nodePath, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}

	got, err := findNode("22")
	if err != nil {
		t.Fatal(err)
	}
	if got != nodePath {
		t.Fatalf("node path = %q, want %q", got, nodePath)
	}
}

func TestFindNodeUsesExplicitOverride(t *testing.T) {
	nodePath := filepath.Join(t.TempDir(), "node")
	t.Setenv("ADVERSARY_NODE_PATH", nodePath)

	got, err := findNode("22")
	if err != nil {
		t.Fatal(err)
	}
	if got != nodePath {
		t.Fatalf("node path = %q, want %q", got, nodePath)
	}
}

func TestPrintExecutionSummaryLabelsHostProcess(t *testing.T) {
	var out bytes.Buffer
	printExecutionSummary(&out, ContainerResult{ExitCode: 0, Kind: "Process"}, 0, time.Millisecond, time.Millisecond)
	if !strings.Contains(out.String(), "Process exit code: 0") {
		t.Fatalf("summary = %q", out.String())
	}
}
