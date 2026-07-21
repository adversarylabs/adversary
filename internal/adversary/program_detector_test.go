package adversary

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adversarylabs/adversary/pkg/detection"
)

type detectorExecutor struct {
	backend ExecutorBackend
	called  bool
	context detection.Context
	result  string
}

func (e *detectorExecutor) Backend() ExecutorBackend         { return e.backend }
func (*detectorExecutor) Capabilities() ExecutorCapabilities { return allTestExecutorCapabilities() }
func (e *detectorExecutor) Run(_ context.Context, spec RuntimeSpec) (RuntimeResult, error) {
	e.called = true
	data, err := os.ReadFile(spec.Env["ADVERSARY_DETECTION_INPUT"])
	if err != nil {
		return RuntimeResult{}, err
	}
	if err := json.Unmarshal(data, &e.context); err != nil {
		return RuntimeResult{}, err
	}
	return RuntimeResult{}, os.WriteFile(spec.Env["ADVERSARY_DETECTION_OUTPUT"], []byte(e.result), 0644)
}

func TestProgrammaticDetectorReceivesCanonicalContextAndResult(t *testing.T) {
	project := detectorProject(t)
	executor := &detectorExecutor{backend: HostExecutorBackend, result: `{"schemaVersion":"adversary.detection.v1","applicable":true,"confidence":"medium","reasons":["framework configuration changed"],"relevantFiles":["src/app.ts"]}`}
	resolved := detection.Context{SchemaVersion: detection.SchemaVersion, RepositoryRoot: t.TempDir(), Mode: detection.ModeDirtyWorktree, ChangedFiles: []detection.ChangedFile{{Path: "src/app.ts", Status: detection.StatusModified}}}
	result, err := (Runner{Executor: executor}).Detect(context.Background(), DetectOptions{AdversaryRef: project, RepoPath: resolved.RepositoryRoot, ReviewContext: resolved})
	if err != nil {
		t.Fatal(err)
	}
	if !executor.called || executor.context.RepositoryRoot != "/workspace" || !result.Applicable || result.Confidence != detection.ConfidenceMedium {
		t.Fatalf("execution context=%#v result=%#v", executor.context, result)
	}
}

type forceUnknownTrust struct{}

func (forceUnknownTrust) Evaluate(identity PublisherIdentity) TrustDecision {
	identity.Local = false
	identity.Name = "unknown"
	return TrustDecision{Publisher: identity, Trust: UnknownPublisherTrust}
}

func TestUnknownProgrammaticDetectorCannotUseHostBeforeReview(t *testing.T) {
	executor := &detectorExecutor{backend: HostExecutorBackend, result: `{}`}
	_, err := (Runner{Executor: executor, TrustPolicy: forceUnknownTrust{}}).Detect(context.Background(), DetectOptions{AdversaryRef: detectorProject(t), RepoPath: t.TempDir(), ReviewContext: detection.Context{SchemaVersion: detection.SchemaVersion, Mode: detection.ModeDirtyWorktree}})
	if err == nil || !strings.Contains(err.Error(), "cannot execute with HostExecutor") {
		t.Fatalf("error = %v", err)
	}
	if executor.called {
		t.Fatal("untrusted detector reached HostExecutor")
	}
}

func TestDecodeDetectionResultRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "result.json")
	if err := os.WriteFile(path, []byte(`{"schemaVersion":"adversary.detection.v1","applicable":true,"confidence":"high","reasons":["match"],"findings":[]}`), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeDetectionResult(OSRuntimeFiles{}, path); err == nil {
		t.Fatal("decoder accepted detector findings")
	}
}

func detectorProject(t *testing.T) string {
	t.Helper()
	project := t.TempDir()
	writeFile(t, filepath.Join(project, "adversary.yaml"), `name: local/detector
detection:
  entrypoint: dist/detect.js
runtime:
  name: node
  version: "22"
  command: [dist/index.js]
`)
	writeFile(t, filepath.Join(project, "dist", "detect.js"), "")
	writeFile(t, filepath.Join(project, "dist", "index.js"), "")
	return project
}
