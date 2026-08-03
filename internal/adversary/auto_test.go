package adversary

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
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
		"container/dockerfile:1.0.0": "name: container/dockerfile\ndetection:\n  files: [Dockerfile]\n",
		"lang/go:1.0.0":              "name: lang/go\ndetection:\n  files: ['**/*.go']\n",
	})
	changes := &fakeChangeResolver{context: detection.Context{SchemaVersion: detection.SchemaVersion, RepositoryRoot: t.TempDir(), Mode: detection.ModeDirtyWorktree, ChangedFiles: []detection.ChangedFile{{Path: "Dockerfile", Status: detection.StatusModified}, {Path: "cmd/main.go", Status: detection.StatusModified}}}}
	reported := false
	executor := &autoRecordingExecutor{reportedBefore: &reported}
	runner := Runner{Resolver: &resolver, Repository: &repo, RequireInjectedResolver: true, Executor: executor, Stdout: os.Stdout, Stderr: os.Stderr}
	result, err := (AutoRunner{Runner: runner, Changes: changes, Resolver: &resolver}).Auto(context.Background(), AutoOptions{MinimumConfidence: detection.ConfidenceMedium, ReportSelections: func(AutoResult) error { reported = true; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if changes.calls != 1 || len(executor.contexts) != 2 || !reflect.DeepEqual(executor.contexts[0], executor.contexts[1]) || !reflect.DeepEqual(executor.contexts[0].ChangedFiles, result.Context.ChangedFiles) || executor.contexts[0].RepositoryRoot != "/workspace" || result.Context.RepositoryRoot != changes.context.RepositoryRoot {
		t.Fatalf("calls=%d contexts=%#v result=%#v", changes.calls, executor.contexts, result.Context)
	}
	if len(result.Selections) != 2 || !result.Selections[0].Selected || !result.Selections[1].Selected {
		t.Fatalf("selections = %#v", result.Selections)
	}
}

func TestAutoDryRunIncludeExcludeAndNoMatch(t *testing.T) {
	_, resolver := autoRepository(t, map[string]string{
		"docs/markdown:1.0.0": "name: docs/markdown\ndetection:\n  files: ['**/*.md']\n",
		"go/security:1.0.0":   "name: go/security\n",
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
		"container/dockerfile:1.0.0": "name: container/dockerfile\ndetection:\n  files: [Dockerfile]\n  entrypoint: dist/detect.js\npermissions:\n  enforcement: required\n  network: false\n",
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
		"container/dockerfile:1.0.0": "name: container/dockerfile\ndetection:\n  files: [Dockerfile]\n  entrypoint: dist/detect.js\n",
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
	forced, err := (AutoRunner{Runner: Runner{Resolver: &resolver, Repository: &repo, Executor: executor}, Changes: changes, Resolver: &resolver}).Auto(context.Background(), AutoOptions{DryRun: true, Includes: []string{"container/dockerfile"}, MinimumConfidence: detection.ConfidenceMedium})
	if err != nil {
		t.Fatal(err)
	}
	if !forced.Selections[0].Selected || !forced.Selections[0].Forced {
		t.Fatalf("forced detector selection = %#v", forced.Selections)
	}
}

func TestAvailableCandidatesDoNotCollapseAcrossPublishers(t *testing.T) {
	// Distinct package bytes under different third-party publishers stay separate.
	// (Official free-catalog paths collapse by package family — see flat/domain test.)
	repo := repository.Repository{Root: t.TempDir()}
	t.Cleanup(func() { makeResolverWritable(repo.Root) })
	for _, item := range []struct {
		ref     string
		version string
		command string
	}{
		{"registry.example/acme/security:1.0.0", "1.0.0", "dist/official.js"},
		{"registry.example/randomperson/security:2.0.0", "2.0.0", "dist/community.js"},
	} {
		project := t.TempDir()
		writeFile(t, filepath.Join(project, "adversary.yaml"), "name: shared/security\nversion: "+item.version+"\nruntime:\n  name: node\n  version: \"22\"\n  command: ["+strconv.Quote(item.command)+"]\n")
		writeFile(t, filepath.Join(project, item.command), "export {}\n")
		artifact, err := pack.Create(context.Background(), pack.Options{Dir: project})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := repo.ImportPacked(artifact, item.ref); err != nil {
			t.Fatal(err)
		}
	}
	resolver := Resolver{Repository: repo}
	candidates, err := (AutoRunner{Runner: Runner{Resolver: &resolver}, Resolver: &resolver}).availableCandidates(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 2 {
		t.Fatalf("candidates = %#v", candidates)
	}
	refs := map[string]bool{}
	for _, candidate := range candidates {
		refs[candidate.Reference] = true
	}
	if !refs["registry.example/acme/security:1.0.0"] || !refs["registry.example/randomperson/security:2.0.0"] {
		t.Fatalf("publisher refs = %#v", refs)
	}
}

func TestAvailableCandidatesCollapseSharedDigestAcrossNamespaces(t *testing.T) {
	// Same digest under multiple domain-path tags collapses to one candidate.
	// (Retired library/* and adversarylabs/* publisher paths are skipped entirely.)
	repo := repository.Repository{Root: t.TempDir()}
	t.Cleanup(func() { makeResolverWritable(repo.Root) })
	project := t.TempDir()
	writeFile(t, filepath.Join(project, "adversary.yaml"), "name: go/cli\nversion: 0.0.15\nruntime:\n  name: node\n  version: \"22\"\n  command: [dist/index.js]\n")
	writeFile(t, filepath.Join(project, "dist", "index.js"), "")
	writeFile(t, filepath.Join(project, "dist", "detect.js"), "")
	artifact, err := pack.Create(context.Background(), pack.Options{Dir: project})
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{
		"registry.adversarylabs.ai/go/cli:0.0.15",
		"registry.adversarylabs.ai/go/cli:latest",
		"localhost:8787/go/cli:0.0.15",
	} {
		if _, err := repo.ImportPacked(artifact, ref); err != nil {
			t.Fatal(err)
		}
	}
	resolver := Resolver{Repository: repo}
	candidates, err := (AutoRunner{Runner: Runner{Resolver: &resolver}, Resolver: &resolver}).availableCandidates(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 {
		t.Fatalf("candidates = %#v", candidates)
	}
	if !strings.Contains(candidates[0].Reference, "go/cli") {
		t.Fatalf("preferred reference = %q, want go/cli", candidates[0].Reference)
	}
	// Prefer official registry over localhost when the digest is shared.
	if strings.Contains(candidates[0].Reference, "localhost") {
		t.Fatalf("preferred reference = %q, want official registry over localhost", candidates[0].Reference)
	}
}

func TestAvailableCandidatesCollapseSamePublisherPackageRename(t *testing.T) {
	// Same domain package under older and newer versions should run once,
	// newest version preferred (historical path renames share family key).
	repo := repository.Repository{Root: t.TempDir()}
	t.Cleanup(func() { makeResolverWritable(repo.Root) })
	for _, item := range []struct {
		ref     string
		name    string
		version string
	}{
		{"registry.adversarylabs.ai/ci/depot:0.0.4", "ci/depot", "0.0.4"},
		{"registry.adversarylabs.ai/ci/depot:0.0.8", "ci/depot", "0.0.8"},
	} {
		project := t.TempDir()
		writeFile(t, filepath.Join(project, "adversary.yaml"), "name: "+item.name+"\nversion: "+item.version+"\nruntime:\n  name: node\n  version: \"22\"\n  command: [dist/index.js]\n")
		writeFile(t, filepath.Join(project, "dist", "index.js"), item.version+"\n")
		artifact, err := pack.Create(context.Background(), pack.Options{Dir: project})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := repo.ImportPacked(artifact, item.ref); err != nil {
			t.Fatal(err)
		}
	}
	resolver := Resolver{Repository: repo}
	candidates, err := (AutoRunner{Runner: Runner{Resolver: &resolver}, Resolver: &resolver}).availableCandidates(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 {
		t.Fatalf("candidates = %#v", candidates)
	}
	if candidates[0].Manifest.Version != "0.0.8" {
		t.Fatalf("version = %q, want 0.0.8", candidates[0].Manifest.Version)
	}
}

func TestAvailableCandidatesCollapseFlatAndDomainCatalogNames(t *testing.T) {
	// Historical flat installs (go-cli, dockerfile) must not double-run alongside
	// modern domain catalog packages (go/cli, container/dockerfile).
	repo := repository.Repository{Root: t.TempDir()}
	t.Cleanup(func() { makeResolverWritable(repo.Root) })
	for _, item := range []struct {
		ref     string
		name    string
		version string
	}{
		{"registry.adversarylabs.ai/go/cli:0.0.21", "go/cli", "0.0.21"},
		{"localhost:8787/go-cli:0.0.18", "go-cli", "0.0.18"},
		{"registry.adversarylabs.ai/container/dockerfile:0.0.13", "container/dockerfile", "0.0.13"},
		{"localhost:8787/dockerfile:0.0.11", "dockerfile", "0.0.11"},
		{"registry.adversarylabs.ai/security/secrets:0.0.12", "security/secrets", "0.0.12"},
		{"localhost:8787/secrets:0.0.9", "secrets", "0.0.9"},
		{"registry.adversarylabs.ai/review/engineering:0.0.11", "review/engineering", "0.0.11"},
		{"localhost:8787/engineering-review:0.0.7", "engineering-review", "0.0.7"},
	} {
		project := t.TempDir()
		writeFile(t, filepath.Join(project, "adversary.yaml"), "name: "+item.name+"\nversion: "+item.version+"\nruntime:\n  name: node\n  version: \"22\"\n  command: [dist/index.js]\n")
		writeFile(t, filepath.Join(project, "dist", "index.js"), item.version+"\n")
		artifact, err := pack.Create(context.Background(), pack.Options{Dir: project})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := repo.ImportPacked(artifact, item.ref); err != nil {
			t.Fatal(err)
		}
	}
	// Retired official publisher path should be ignored entirely.
	project := t.TempDir()
	writeFile(t, filepath.Join(project, "adversary.yaml"), "name: go-cli\nversion: 0.0.1\nruntime:\n  name: node\n  version: \"22\"\n  command: [dist/index.js]\n")
	writeFile(t, filepath.Join(project, "dist", "index.js"), "retired\n")
	artifact, err := pack.Create(context.Background(), pack.Options{Dir: project})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.ImportPacked(artifact, "registry.adversarylabs.ai/library/go-cli:0.0.1"); err != nil {
		t.Fatal(err)
	}
	// Meta package stays eligible (not retired).
	metaProject := t.TempDir()
	writeFile(t, filepath.Join(metaProject, "adversary.yaml"), "name: adversarylabs/adversary\nversion: 0.0.24\nruntime:\n  name: node\n  version: \"22\"\n  command: [dist/index.js]\n")
	writeFile(t, filepath.Join(metaProject, "dist", "index.js"), "meta\n")
	metaArtifact, err := pack.Create(context.Background(), pack.Options{Dir: metaProject})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.ImportPacked(metaArtifact, "registry.adversarylabs.ai/adversarylabs/adversary:0.0.24"); err != nil {
		t.Fatal(err)
	}

	resolver := Resolver{Repository: repo}
	candidates, err := (AutoRunner{Runner: Runner{Resolver: &resolver}, Resolver: &resolver}).availableCandidates(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 5 {
		t.Fatalf("want 5 families (cli, dockerfile, secrets, engineering, meta), got %#v", candidates)
	}
	byName := map[string]DetectionCandidate{}
	for _, c := range candidates {
		byName[c.Name] = c
	}
	for _, want := range []struct {
		name    string
		version string
	}{
		{"go/cli", "0.0.21"},
		{"container/dockerfile", "0.0.13"},
		{"security/secrets", "0.0.12"},
		{"review/engineering", "0.0.11"},
		{"adversarylabs/adversary", "0.0.24"},
	} {
		got, ok := byName[want.name]
		if !ok {
			t.Fatalf("missing preferred domain package %q in %#v", want.name, byName)
		}
		if got.Manifest.Version != want.version {
			t.Fatalf("%s version = %q, want %q", want.name, got.Manifest.Version, want.version)
		}
	}
}

func TestAvailableCandidatesPreferNewestVersionPerRepository(t *testing.T) {
	repo := repository.Repository{Root: t.TempDir()}
	t.Cleanup(func() { makeResolverWritable(repo.Root) })
	for _, version := range []string{"0.0.5", "0.0.6"} {
		project := t.TempDir()
		writeFile(t, filepath.Join(project, "adversary.yaml"), "name: review/engineering\nversion: "+version+"\nruntime:\n  name: node\n  version: \"22\"\n  command: [dist/index.js]\n")
		writeFile(t, filepath.Join(project, "dist", "index.js"), "")
		writeFile(t, filepath.Join(project, "dist", "detect.js"), "")
		artifact, err := pack.Create(context.Background(), pack.Options{Dir: project})
		if err != nil {
			t.Fatal(err)
		}
		ref := "registry.adversarylabs.ai/review/engineering:" + version
		if _, err := repo.ImportPacked(artifact, ref); err != nil {
			t.Fatal(err)
		}
	}
	resolver := Resolver{Repository: repo}
	candidates, err := (AutoRunner{Runner: Runner{Resolver: &resolver}, Resolver: &resolver}).availableCandidates(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 {
		t.Fatalf("candidates = %#v", candidates)
	}
	if candidates[0].Manifest.Version != "0.0.6" {
		t.Fatalf("version = %q, want 0.0.6", candidates[0].Manifest.Version)
	}
	if !strings.HasSuffix(candidates[0].Reference, ":0.0.6") {
		t.Fatalf("reference = %q, want :0.0.6 tag", candidates[0].Reference)
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
		rec, err := repo.ImportPacked(artifact, reference)
		if err != nil {
			t.Fatal(err)
		}
		// Catalog-style packages used in auto tests are treated as officially signed
		// so HostExecutor detection policy matches production after signature MVP.
		if !strings.HasPrefix(reference, "ghcr.io/") && !strings.HasPrefix(reference, "randomperson/") {
			priv := testOfficialSigningKey(t)
			signOfficialDigest(t, repo, rec.Digest, priv)
		}
	}
	return repo, Resolver{Repository: repo}
}
