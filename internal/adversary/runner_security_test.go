package adversary

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type outputExecutor struct {
	output []byte
	log    string
}

func (e outputExecutor) Run(_ context.Context, spec ContainerSpec) (ContainerResult, error) {
	if e.log != "" {
		// Custom executors do not own Runner's streams; protocol tests use the
		// production HostExecutor below for stream routing.
	}
	if e.output != nil {
		if err := os.WriteFile(filepath.Join(spec.RunDir, "output.json"), e.output, 0644); err != nil {
			return ContainerResult{}, err
		}
	}
	return ContainerResult{Kind: "Process"}, nil
}

func minimalEnvelope() []byte {
	return []byte(`{"protocolVersion":1,"result":{"adversary":{"name":"local/test"},"target":{},"positives":[],"observations":[],"findings":[],"suppressed":{"observations":0,"findings":0}}}`)
}

func writeRunnerProject(t *testing.T, permissions string) string {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "adversary.yaml"), "name: local/test\nruntime:\n  name: node\n  version: \"22\"\n  command:\n    - index.js\n"+permissions)
	return dir
}

func TestRunFailsClosedForHostNetworkRestriction(t *testing.T) {
	project := writeRunnerProject(t, "permissions:\n  network: false\n")
	err := Runner{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}.Run(context.Background(), RunOptions{AdversaryRef: project, RepoPath: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "cannot enforce disabled network") {
		t.Fatalf("error = %v", err)
	}
}

func TestRunFailsClosedForHostManifestRestrictions(t *testing.T) {
	project := writeRunnerProject(t, "permissions:\n  env:\n    - HOME\n")
	err := Runner{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}.Run(context.Background(), RunOptions{AdversaryRef: project, RepoPath: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "cannot enforce manifest") {
		t.Fatalf("error = %v", err)
	}
}

func TestRunRequiresAcknowledgementForNonPathReference(t *testing.T) {
	resolved := ResolvedAdversary{LocalDir: true}
	err := validateHostExecution(resolved, false, RunOptions{})
	if err == nil || !strings.Contains(err.Error(), "--allow-unsafe-host-execution") {
		t.Fatalf("error = %v", err)
	}
	if err := validateHostExecution(resolved, false, RunOptions{AllowUnsafeHostExecution: true}); err != nil {
		t.Fatal(err)
	}
}

func TestRunShellRequiresAcknowledgementAndRejectsJSON(t *testing.T) {
	resolved := ResolvedAdversary{LocalDir: true}
	if err := validateHostExecution(resolved, true, RunOptions{Shell: true}); err == nil {
		t.Fatal("expected acknowledgement error")
	}
	err := validateHostExecution(resolved, true, RunOptions{Shell: true, Format: "json", AllowUnsafeHostExecution: true})
	if err == nil || !strings.Contains(err.Error(), "cannot be combined") {
		t.Fatalf("error = %v", err)
	}
}

func TestRunMissingEmptyAndOversizedOutputAreProtocolFailures(t *testing.T) {
	project := writeRunnerProject(t, "")
	for name, output := range map[string][]byte{
		"missing":   nil,
		"empty":     {},
		"oversized": bytes.Repeat([]byte("x"), int(maxRunOutputBytes)+1),
		"invalid":   []byte(`{"protocolVersion":1}`),
	} {
		t.Run(name, func(t *testing.T) {
			err := Runner{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}, Executor: outputExecutor{output: output}}.Run(context.Background(), RunOptions{AdversaryRef: project, RepoPath: t.TempDir()})
			if err == nil || !strings.Contains(err.Error(), "protocol failure") {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestRunJSONKeepTempIsOneDocumentAndPathIsStderr(t *testing.T) {
	project := writeRunnerProject(t, "")
	var stdout, stderr bytes.Buffer
	err := Runner{Stdout: &stdout, Stderr: &stderr, Executor: outputExecutor{output: minimalEnvelope()}}.Run(context.Background(), RunOptions{AdversaryRef: project, RepoPath: t.TempDir(), Format: "json", KeepTemp: true})
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	decoder := json.NewDecoder(&stdout)
	if err := decoder.Decode(&document); err != nil {
		t.Fatal(err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		t.Fatalf("stdout contains trailing data: %q (decode error %v)", stdout.String(), err)
	}
	if strings.Contains(stdout.String(), "Temporary run directory") {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "Temporary run directory") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestHostChildStdoutIsRoutedToStderr(t *testing.T) {
	project := writeRunnerProject(t, "")
	script := filepath.Join(project, "run.sh")
	writeFile(t, script, "#!/bin/sh\nprintf 'child log\\n'\nprintf '%s' '"+string(minimalEnvelope())+"' > \"$ADVERSARY_OUTPUT\"\n")
	if err := os.Chmod(script, 0755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(project, "adversary.yaml"), "name: local/test\nruntime:\n  name: process\n  version: \"1\"\n  command:\n    - "+script+"\n")

	var stdout, stderr bytes.Buffer
	err := Runner{Stdout: &stdout, Stderr: &stderr}.Run(context.Background(), RunOptions{AdversaryRef: project, RepoPath: t.TempDir(), Format: "json"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout.String(), "child log") {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "child log") {
		t.Fatalf("stderr = %q", stderr.String())
	}
	var envelope map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
		t.Fatalf("stdout is not pure JSON: %v\n%s", err, stdout.String())
	}
}
