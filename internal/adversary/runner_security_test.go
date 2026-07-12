package adversary

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/adversarylabs/adversary/pkg/review"
)

type outputExecutor struct {
	output []byte
	log    string
}

type cancelExecutor struct{}

func (cancelExecutor) Run(ctx context.Context, _ ContainerSpec) (ContainerResult, error) {
	<-ctx.Done()
	return ContainerResult{ExitCode: -1, Kind: "Process"}, ctx.Err()
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

func suppressedEnvelope() []byte {
	return []byte(`{"protocolVersion":1,"result":{"adversary":{"name":"local/test"},"target":{},"positives":[],"observations":[],"findings":[],"suppressed":{"observations":2,"findings":1},"suppressedFindings":[{"id":"hidden","title":"HIDDEN-DETAIL-\u001b[2J","category":"test","severity":"low","confidence":"high","summary":"hidden summary","evidence":[]}]}}`)
}

func TestRunEnforcesSuppressedDetailDisclosureForTextAndJSON(t *testing.T) {
	for _, format := range []string{"text", "json"} {
		for _, include := range []bool{false, true} {
			name := format + "/excluded"
			if include {
				name = format + "/included"
			}
			t.Run(name, func(t *testing.T) {
				project := writeRunnerProject(t, "")
				var stdout bytes.Buffer
				err := Runner{Stdout: &stdout, Stderr: &bytes.Buffer{}, Executor: outputExecutor{output: suppressedEnvelope()}}.Run(context.Background(), RunOptions{
					AdversaryRef: project, RepoPath: t.TempDir(), Format: format, IncludeSuppressed: include,
				})
				if err != nil {
					t.Fatal(err)
				}
				if format == "text" {
					got := stdout.String()
					if !strings.Contains(got, "Suppressed observations: 2") || !strings.Contains(got, "Suppressed findings: 1") {
						t.Fatalf("aggregate counts missing: %q", got)
					}
					if strings.Contains(got, "\x1b") {
						t.Fatalf("terminal control leaked: %q", got)
					}
					if strings.Contains(got, "HIDDEN-DETAIL") != include {
						t.Fatalf("detail inclusion = %t, want %t: %q", strings.Contains(got, "HIDDEN-DETAIL"), include, got)
					}
					return
				}
				var envelope review.RunEnvelope
				if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
					t.Fatalf("JSON output: %v: %q", err, stdout.String())
				}
				if envelope.Result.Suppressed.Findings != 1 || envelope.Result.Suppressed.Observations != 2 {
					t.Fatalf("aggregate counts = %+v", envelope.Result.Suppressed)
				}
				if (len(envelope.Result.SuppressedFindings) == 1) != include {
					t.Fatalf("suppressed details = %#v; include=%t", envelope.Result.SuppressedFindings, include)
				}
				if include && !strings.Contains(envelope.Result.SuppressedFindings[0].Title, "\x1b[2J") {
					t.Fatalf("JSON protocol data was unexpectedly terminal-sanitized: %#v", envelope.Result.SuppressedFindings[0])
				}
			})
		}
	}
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

func TestEmptyPermissionListsDoNotRequestHostBoundary(t *testing.T) {
	project := writeRunnerProject(t, "permissions:\n  filesystem:\n    read: []\n    write: []\n  env: []\n")
	resolved, err := ResolveReference(project)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateHostExecution(resolved, true, RunOptions{}); err != nil {
		t.Fatalf("empty lists should have current compatibility semantics: %v", err)
	}
}

func TestExplicitPathClassificationRejectsArtifactStorage(t *testing.T) {
	home := t.TempDir()
	data := filepath.Join(t.TempDir(), "data")
	t.Setenv("HOME", home)
	t.Setenv("ADVERSARY_DATA_DIR", data)

	unifiedProject := filepath.Join(data, "repository-v1", "materialized", "artifact")
	legacyStoreProject := filepath.Join(data, "materialized", "artifact")
	legacyCacheProject := filepath.Join(home, ".adversary", "cache", "artifacts", "artifact")
	localProject := filepath.Join(t.TempDir(), "source")
	for _, project := range []string{unifiedProject, legacyStoreProject, legacyCacheProject, localProject} {
		if err := os.MkdirAll(project, 0755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(project, "adversary.yaml"), "name: local/test\nruntime:\n  name: node\n  version: \"22\"\n  command: [dist/index.js]\n")
	}

	for name, project := range map[string]string{
		"unified repository": unifiedProject,
		"retired store":      legacyStoreProject,
		"retired cache":      legacyCacheProject,
	} {
		t.Run(name, func(t *testing.T) {
			explicit, err := isExplicitLocalAdversaryPath(project)
			if err != nil {
				t.Fatal(err)
			}
			if explicit {
				t.Fatalf("artifact storage path %q classified as explicit local source", project)
			}
			home, _ := os.UserHomeDir()
			err = Runner{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}, HomeDir: home, DataRoot: data}.Run(context.Background(), RunOptions{AdversaryRef: project, RepoPath: t.TempDir()})
			if err == nil || !strings.Contains(err.Error(), "--allow-unsafe-host-execution") {
				t.Fatalf("direct artifact path error = %v", err)
			}
		})
	}

	explicit, err := isExplicitLocalAdversaryPath(localProject)
	if err != nil || !explicit {
		t.Fatalf("absolute local path: explicit=%v, error=%v", explicit, err)
	}
	parent := filepath.Dir(localProject)
	t.Chdir(parent)
	explicit, err = isExplicitLocalAdversaryPath(filepath.Base(localProject))
	if err != nil || !explicit {
		t.Fatalf("relative local path: explicit=%v, error=%v", explicit, err)
	}
}

func TestDefaultPlatformStorePathRequiresAcknowledgement(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("ADVERSARY_DATA_DIR", "")
	roots, err := artifactStorageRoots()
	if err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(roots[0], "repository-v1", "materialized", "artifact")
	if err := os.MkdirAll(project, 0755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(project, "adversary.yaml"), "name: local/test\nruntime:\n  name: node\n  version: \"22\"\n")
	explicit, err := isExplicitLocalAdversaryPath(project)
	if err != nil {
		t.Fatal(err)
	}
	if explicit {
		t.Fatalf("default store path %q classified as explicit local source", project)
	}
}

func TestArtifactStorageSymlinkCannotBypassAcknowledgement(t *testing.T) {
	home := t.TempDir()
	data := filepath.Join(t.TempDir(), "data")
	t.Setenv("HOME", home)
	t.Setenv("ADVERSARY_DATA_DIR", data)
	materializedProject := filepath.Join(data, "repository-v1", "materialized", "artifact")
	if err := os.MkdirAll(materializedProject, 0755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(materializedProject, "adversary.yaml"), "name: local/test\nruntime:\n  name: node\n  version: \"22\"\n")
	link := filepath.Join(t.TempDir(), "apparently-local")
	if err := os.Symlink(materializedProject, link); err != nil {
		t.Fatal(err)
	}
	explicit, err := isExplicitLocalAdversaryPath(link)
	if err != nil {
		t.Fatal(err)
	}
	if explicit {
		t.Fatal("symlink into unified materialization classified as explicit local source")
	}
}

func TestRunJSONTriggerSkipIsOneVersionedEnvelope(t *testing.T) {
	project := writeRunnerProject(t, "")
	writeFile(t, filepath.Join(project, "adversary.yaml"), `name: local/test
triggers:
  files_changed:
    - "Dockerfile"
runtime:
  name: node
  version: "22"
  command:
    - index.js
`)
	repo := t.TempDir()
	var stdout, stderr bytes.Buffer
	executor := &recordingExecutor{}
	err := Runner{Stdout: &stdout, Stderr: &stderr, Git: fakeGitDiffer{files: []string{"README.md"}}, Executor: executor}.Run(context.Background(), RunOptions{
		AdversaryRef: project, RepoPath: repo, BaseRef: "main", HeadRef: "HEAD", Format: "json", KeepTemp: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if executor.called {
		t.Fatal("executor was called")
	}
	want := "{\n  \"protocolVersion\": 1,\n  \"result\": {\n    \"adversary\": {\n      \"name\": \"local/test\"\n    },\n    \"target\": {\n      \"repository\": " + string(mustJSON(t, repo)) + "\n    },\n    \"positives\": [],\n    \"observations\": [\n      {\n        \"key\": \"run-skipped\",\n        \"summary\": \"No changed files matched triggers.files_changed.\"\n      }\n    ],\n    \"findings\": [],\n    \"suppressed\": {\n      \"observations\": 0,\n      \"findings\": 0\n    }\n  }\n}\n"
	if stdout.String() != want {
		t.Fatalf("JSON skip output mismatch\nwant:\n%s\ngot:\n%s", want, stdout.String())
	}
	if _, err := review.DecodeRunEnvelope(stdout.Bytes()); err != nil {
		t.Fatalf("skip envelope is not protocol-valid: %v", err)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func mustJSON(t *testing.T, value string) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
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
	canonicalProject, err := filepath.EvalSymlinks(project)
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(canonicalProject, "run.sh")
	writeFile(t, script, "#!/bin/sh\nprintf 'child log\\n'\nprintf '%s' '"+string(minimalEnvelope())+"' > \"$ADVERSARY_OUTPUT\"\n")
	if err := os.Chmod(script, 0755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(project, "adversary.yaml"), "name: local/test\nruntime:\n  name: process\n  version: \"1\"\n  command:\n    - "+script+"\n")

	var stdout, stderr bytes.Buffer
	err = Runner{Stdout: &stdout, Stderr: &stderr, Executor: systemHostExecutorForTest(nil, &stderr, &stderr)}.Run(context.Background(), RunOptions{AdversaryRef: project, RepoPath: t.TempDir(), Format: "json"})
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

func TestRunCleansTemporaryDirectoryAfterExecutorReturns(t *testing.T) {
	project := writeRunnerProject(t, "")
	parent := t.TempDir()
	runDir := filepath.Join(parent, "run")
	err := Runner{
		Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}, Executor: outputExecutor{output: minimalEnvelope()},
		MkdirTemp: func(string, string) (string, error) {
			if err := os.Mkdir(runDir, 0700); err != nil {
				return "", err
			}
			return runDir, nil
		},
	}.Run(context.Background(), RunOptions{AdversaryRef: project, RepoPath: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(runDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary directory remains: %v", err)
	}
}

func TestRunReportsCleanupFailureOnlyInVerboseDiagnostics(t *testing.T) {
	project := writeRunnerProject(t, "")
	var stderr bytes.Buffer
	err := Runner{
		Stdout: &bytes.Buffer{}, Stderr: &stderr, Executor: outputExecutor{output: minimalEnvelope()},
		RemoveAll: func(string) error { return errors.New("injected cleanup failure") },
	}.Run(context.Background(), RunOptions{AdversaryRef: project, RepoPath: t.TempDir(), Verbose: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr.String(), "injected cleanup failure") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRunTimeoutCleansTemporaryDirectoryAfterChildShutdown(t *testing.T) {
	project := writeRunnerProject(t, "")
	runDir := filepath.Join(t.TempDir(), "run")
	err := Runner{
		Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}, Executor: cancelExecutor{},
		MkdirTemp: func(string, string) (string, error) {
			if err := os.Mkdir(runDir, 0700); err != nil {
				return "", err
			}
			return runDir, nil
		},
	}.Run(context.Background(), RunOptions{AdversaryRef: project, RepoPath: t.TempDir(), RunTimeout: 10 * time.Millisecond})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v", err)
	}
	if _, err := os.Stat(runDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary directory remains: %v", err)
	}
}
