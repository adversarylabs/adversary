package adversary

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/adversarylabs/adversary/pkg/detection"
	"github.com/adversarylabs/adversary/pkg/pack"
	"github.com/adversarylabs/adversary/pkg/repository"
)

type fakeChangeResolver struct {
	context         detection.Context
	repositoryFiles []string
	calls           int
}

func (r *fakeChangeResolver) ResolveChanges(context.Context, ChangeRequest) (detection.Context, error) {
	r.calls++
	return r.context, nil
}
func (r *fakeChangeResolver) RepositoryFiles(context.Context, string) ([]string, error) {
	return append([]string(nil), r.repositoryFiles...), nil
}

type autoRecordingExecutor struct {
	contexts       []detection.Context
	reportedBefore *bool
}

func (*autoRecordingExecutor) Backend() ExecutorBackend { return NativeSandboxExecutorBackend }
func (*autoRecordingExecutor) Capabilities() ExecutorCapabilities {
	return allTestExecutorCapabilities()
}
func (e *autoRecordingExecutor) Run(_ context.Context, spec RuntimeSpec) (RuntimeResult, error) {
	if e.reportedBefore != nil && !*e.reportedBefore {
		return RuntimeResult{}, errors.New("selections were not reported before execution")
	}
	if path := spec.Env["ADVERSARY_CHANGE_CONTEXT"]; path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return RuntimeResult{}, err
		}
		var value detection.Context
		if err := json.Unmarshal(data, &value); err != nil {
			return RuntimeResult{}, err
		}
		e.contexts = append(e.contexts, value)
	}
	output := `{"protocolVersion":1,"result":{"adversary":{"name":"test"},"target":{},"positives":[],"observations":[],"findings":[],"suppressed":{"observations":0,"findings":0}}}`
	return RuntimeResult{}, os.WriteFile(spec.Env["ADVERSARY_OUTPUT"], []byte(output), 0644)
}

func TestAutoSelectsAvailableAdversariesAndSharesOneContext(t *testing.T) {
	repo, resolver := autoRepository(t, map[string]string{
		"adversarylabs/dockerfile:1.0.0": "name: adversarylabs/dockerfile\ndetection:\n  files: [Dockerfile]\n",
		"adversarylabs/general:1.0.0":    "name: adversarylabs/general\ndetection:\n  files: ['**/*.go']\n",
	})
	changes := &fakeChangeResolver{context: detection.Context{SchemaVersion: detection.SchemaVersion, RepositoryRoot: t.TempDir(), Mode: detection.ModeDirtyWorktree, ChangedFiles: []detection.ChangedFile{{Path: "Dockerfile", Status: detection.StatusModified}, {Path: "cmd/main.go", Status: detection.StatusModified}}}}
	reported := false
	executor := &autoRecordingExecutor{reportedBefore: &reported}
	runner := Runner{Resolver: &resolver, Repository: &repo, RequireInjectedResolver: true, Executor: executor, Stdout: os.Stdout, Stderr: os.Stderr}
	result, err := (AutoRunner{Runner: runner, Changes: changes, Resolver: &resolver}).Auto(context.Background(), AutoOptions{MinimumConfidence: detection.ConfidenceMedium, ReportSelections: func(AutoResult) error { reported = true; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if changes.calls != 1 || len(executor.contexts) != 2 || !reflect.DeepEqual(executor.contexts[0], executor.contexts[1]) || !reflect.DeepEqual(executor.contexts[0], result.Context) {
		t.Fatalf("calls=%d contexts=%#v result=%#v", changes.calls, executor.contexts, result.Context)
	}
	if len(result.Selections) != 2 || !result.Selections[0].Selected || !result.Selections[1].Selected {
		t.Fatalf("selections = %#v", result.Selections)
	}
}

func TestAutoDryRunIncludeExcludeAndNoMatch(t *testing.T) {
	_, resolver := autoRepository(t, map[string]string{
		"adversarylabs/docs:1.0.0":     "name: adversarylabs/docs\ndetection:\n  files: ['**/*.md']\n",
		"adversarylabs/security:1.0.0": "name: adversarylabs/security\n",
	})
	changes := &fakeChangeResolver{context: detection.Context{SchemaVersion: detection.SchemaVersion, RepositoryRoot: t.TempDir(), Mode: detection.ModeDirtyWorktree, ChangedFiles: []detection.ChangedFile{{Path: "main.go", Status: detection.StatusModified}}}}
	result, err := (AutoRunner{Runner: Runner{Resolver: &resolver}, Changes: changes, Resolver: &resolver}).Auto(context.Background(), AutoOptions{DryRun: true, Includes: []string{"security"}, Excludes: []string{"security"}, MinimumConfidence: detection.ConfidenceMedium})
	if err != nil {
		t.Fatal(err)
	}
	for _, selection := range result.Selections {
		if selection.Selected {
			t.Fatalf("unexpected selection: %#v", selection)
		}
	}
}

func TestAutoUntrustedProgramDetectorFallsBackToSafeDeclaration(t *testing.T) {
	repo, resolver := autoRepository(t, map[string]string{
		"randomperson/dockerfile:1.0.0": "name: randomperson/dockerfile\ndetection:\n  files: [Dockerfile]\n  entrypoint: dist/detect.js\n",
	})
	changes := &fakeChangeResolver{context: detection.Context{SchemaVersion: detection.SchemaVersion, RepositoryRoot: t.TempDir(), Mode: detection.ModeDirtyWorktree, ChangedFiles: []detection.ChangedFile{{Path: "Dockerfile", Status: detection.StatusModified}}}}
	result, err := (AutoRunner{Runner: Runner{Resolver: &resolver, Repository: &repo, Executor: &detectorExecutor{backend: HostExecutorBackend}}, Changes: changes, Resolver: &resolver}).Auto(context.Background(), AutoOptions{DryRun: true, MinimumConfidence: detection.ConfidenceMedium})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Selections) != 1 || !result.Selections[0].Selected || result.Selections[0].Error == nil {
		t.Fatalf("selection = %#v", result.Selections)
	}
}

func TestAutoPolicyDeniedProgramDetectorFallsBackToSafeDeclaration(t *testing.T) {
	repo, resolver := autoRepository(t, map[string]string{
		"adversarylabs/dockerfile:1.0.0": "name: adversarylabs/dockerfile\ndetection:\n  files: [Dockerfile]\n  entrypoint: dist/detect.js\npermissions:\n  enforcement: required\n  network: false\n",
	})
	changes := &fakeChangeResolver{context: detection.Context{SchemaVersion: detection.SchemaVersion, RepositoryRoot: t.TempDir(), Mode: detection.ModeDirtyWorktree, ChangedFiles: []detection.ChangedFile{{Path: "Dockerfile", Status: detection.StatusModified}}}}
	caps := ExecutorCapabilities{}
	executor := &detectorExecutor{backend: NativeSandboxExecutorBackend, caps: &caps}
	result, err := (AutoRunner{Runner: Runner{Resolver: &resolver, Repository: &repo, Executor: executor}, Changes: changes, Resolver: &resolver}).Auto(context.Background(), AutoOptions{DryRun: true, MinimumConfidence: detection.ConfidenceMedium})
	if err != nil {
		t.Fatal(err)
	}
	if executor.called || len(result.Selections) != 1 || !result.Selections[0].Selected || result.Selections[0].Error == nil {
		t.Fatalf("executor called=%t selection=%#v", executor.called, result.Selections)
	}
}

func TestAutoTrustedDetectorFailureSkipsUnlessForced(t *testing.T) {
	repo, resolver := autoRepository(t, map[string]string{
		"adversarylabs/dockerfile:1.0.0": "name: adversarylabs/dockerfile\ndetection:\n  files: [Dockerfile]\n  entrypoint: dist/detect.js\n",
	})
	changes := &fakeChangeResolver{context: detection.Context{SchemaVersion: detection.SchemaVersion, RepositoryRoot: t.TempDir(), Mode: detection.ModeDirtyWorktree, ChangedFiles: []detection.ChangedFile{{Path: "Dockerfile", Status: detection.StatusModified}}}}
	executor := &detectorExecutor{backend: HostExecutorBackend, result: `{}`}
	result, err := (AutoRunner{Runner: Runner{Resolver: &resolver, Repository: &repo, Executor: executor}, Changes: changes, Resolver: &resolver}).Auto(context.Background(), AutoOptions{DryRun: true, MinimumConfidence: detection.ConfidenceMedium})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Selections) != 1 || result.Selections[0].Selected || result.Selections[0].Error == nil {
		t.Fatalf("failed detector selection = %#v", result.Selections)
	}
	forced, err := (AutoRunner{Runner: Runner{Resolver: &resolver, Repository: &repo, Executor: executor}, Changes: changes, Resolver: &resolver}).Auto(context.Background(), AutoOptions{DryRun: true, Includes: []string{"adversarylabs/dockerfile"}, MinimumConfidence: detection.ConfidenceMedium})
	if err != nil {
		t.Fatal(err)
	}
	if !forced.Selections[0].Selected || !forced.Selections[0].Forced {
		t.Fatalf("forced detector selection = %#v", forced.Selections)
	}
}

func TestAvailableCandidatesDoNotCollapseAcrossPublishers(t *testing.T) {
	_, resolver := autoRepository(t, map[string]string{
		"adversarylabs/security:1.0.0": "name: shared/security\n",
		"randomperson/security:2.0.0":  "name: shared/security\n",
	})
	candidates, err := (AutoRunner{Runner: Runner{Resolver: &resolver}, Resolver: &resolver}).availableCandidates(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 2 {
		t.Fatalf("candidates = %#v", candidates)
	}
}

func TestAutoExecutionErrorIncludesNamedCauses(t *testing.T) {
	err := (&AutoExecutionError{Errors: []error{errors.New("security: sandbox unavailable"), errors.New("docs: protocol failed")}}).Error()
	if !strings.Contains(err, "security: sandbox unavailable") || !strings.Contains(err, "docs: protocol failed") {
		t.Fatalf("error = %q", err)
	}
}

func TestAutoAllBypassesProgrammaticDetection(t *testing.T) {
	_, resolver := autoRepository(t, map[string]string{
		"randomperson/reviewer:1.0.0": "name: randomperson/reviewer\ndetection:\n  entrypoint: dist/detect.js\n",
	})
	changes := &fakeChangeResolver{context: detection.Context{SchemaVersion: detection.SchemaVersion, RepositoryRoot: t.TempDir(), Mode: detection.ModeDirtyWorktree}}
	executor := &detectorExecutor{backend: HostExecutorBackend}
	result, err := (AutoRunner{Runner: Runner{Resolver: &resolver, Executor: executor}, Changes: changes, Resolver: &resolver}).Auto(context.Background(), AutoOptions{DryRun: true, All: true, MinimumConfidence: detection.ConfidenceMedium})
	if err != nil {
		t.Fatal(err)
	}
	if executor.called || len(result.Selections) != 1 || !result.Selections[0].Selected || result.Selections[0].Error != nil {
		t.Fatalf("executor called=%t selections=%#v", executor.called, result.Selections)
	}
}

func TestConfidenceThresholds(t *testing.T) {
	for _, minimum := range []detection.Confidence{detection.ConfidenceHigh, detection.ConfidenceMedium, detection.ConfidenceLow} {
		selections := []DetectionSelection{
			{Candidate: DetectionCandidate{Name: "high"}, Result: detection.Result{Applicable: true, Confidence: detection.ConfidenceHigh}},
			{Candidate: DetectionCandidate{Name: "medium"}, Result: detection.Result{Applicable: true, Confidence: detection.ConfidenceMedium}},
			{Candidate: DetectionCandidate{Name: "low"}, Result: detection.Result{Applicable: true, Confidence: detection.ConfidenceLow}},
		}
		got, err := FilterAndOrderSelections(selections, minimum, nil, nil, false)
		if err != nil {
			t.Fatal(err)
		}
		selected := 0
		for _, selection := range got {
			if selection.Selected {
				selected++
			}
		}
		want := map[detection.Confidence]int{detection.ConfidenceHigh: 1, detection.ConfidenceMedium: 2, detection.ConfidenceLow: 3}[minimum]
		if selected != want {
			t.Fatalf("minimum %s selected %d, want %d", minimum, selected, want)
		}
	}
}

func autoRepository(t *testing.T, manifests map[string]string) (repository.Repository, Resolver) {
	t.Helper()
	repo := repository.Repository{Root: t.TempDir()}
	t.Cleanup(func() { makeResolverWritable(repo.Root) })
	for reference, header := range manifests {
		project := t.TempDir()
		manifest := header + "version: 1.0.0\nruntime:\n  name: node\n  version: \"22\"\n  command: [dist/index.js]\n"
		writeFile(t, filepath.Join(project, "adversary.yaml"), manifest)
		writeFile(t, filepath.Join(project, "dist", "index.js"), "")
		writeFile(t, filepath.Join(project, "dist", "detect.js"), "")
		artifact, err := pack.Create(context.Background(), pack.Options{Dir: project})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := repo.ImportPacked(artifact, reference); err != nil {
			t.Fatal(err)
		}
	}
	return repo, Resolver{Repository: repo}
}
