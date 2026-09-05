package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/pkg/detection"
	"github.com/adversarylabs/adversary/pkg/oci"
	"github.com/adversarylabs/adversary/pkg/repository"
)

type selectionTestRegistry struct {
	application.OCIRegistry
	batches [][]oci.Reference
}

func (r *selectionTestRegistry) MetadataBatch(_ context.Context, refs []oci.Reference) map[string]oci.Metadata {
	r.batches = append(r.batches, refs)
	out := map[string]oci.Metadata{}
	for _, ref := range refs {
		yaml := "name: " + ref.Repository + "\nversion: 1.0.0\nruntime:\n  name: node\n  version: '22'\n  command: [dist/index.js]\n"
		switch ref.Repository {
		case "review/code":
			yaml += "uses:\n  - name: registry.test/lang/go\n    version: 1.0.0\n  - name: registry.test/lang/python\n    version: 1.0.0\n"
		case "lang/go":
			yaml += "detection:\n  files: ['**/*.go']\n"
		case "lang/python":
			yaml += "detection:\n  files: ['**/*.py']\n"
		}
		out[ref.Locator()] = oci.Metadata{Digest: "sha256:" + strings.Repeat("a", 64), Manifest: yaml}
	}
	return out
}

type selectionTestFactory struct {
	err      error
	registry *selectionTestRegistry
	inner    application.RegistryFactory
}

func (f selectionTestFactory) BindingIdentity() string {
	return f.inner.(application.BindingIdentity).BindingIdentity()
}

func (f selectionTestFactory) New(string, string) (application.OCIRegistry, error) {
	return f.registry, f.err
}

type selectionTestRuntime struct{ application.Runtime }

func (r selectionTestRuntime) composeSelectionContext(context.Context, *runOptions) (*detection.Context, error) {
	return &detection.Context{RepositoryFiles: []string{"main.go"}}, nil
}
func TestComposePlanColdCacheSelectsWithoutPullingOrRunning(t *testing.T) {
	var out, progress bytes.Buffer
	base := lifecycleTestApp(t, repository.Repository{Root: t.TempDir()}, &out, &progress)
	deps := base.Dependencies()
	registry := &selectionTestRegistry{}
	deps.Registries = selectionTestFactory{registry: registry, inner: deps.Registries}
	deps.Runtime = selectionTestRuntime{deps.Runtime}
	app, err := application.New(deps)
	if err != nil {
		t.Fatal(err)
	}
	cmd := NewRootCommandWithApp(app)
	cmd.SetArgs([]string{"run", "registry.test/review/code:1.0.0", "--compose-plan", "--format", "json"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	var plan application.ComposePlan
	if err := json.Unmarshal(out.Bytes(), &plan); err != nil {
		t.Fatalf("%v: %s", err, out.String())
	}
	if len(plan.Refs) != 2 || len(plan.Selections) != 3 || plan.Selections[2].Selected {
		t.Fatalf("bad selection: %+v", plan)
	}
	if len(registry.batches) != 2 || len(registry.batches[1]) != 2 {
		t.Fatalf("not batched: %+v", registry.batches)
	}
	if !strings.Contains(plan.Refs[1], "@sha256:") {
		t.Fatalf("not digest pinned: %v", plan.Refs)
	}
	if strings.Contains(progress.String(), "Pulling") {
		t.Fatal("preview pulled packages")
	}
}

func TestComposePlanPreservesRegistryFactoryFailure(t *testing.T) {
	var out, progress bytes.Buffer
	deps := lifecycleTestApp(t, repository.Repository{Root: t.TempDir()}, &out, &progress).Dependencies()
	want := &selectionFactoryError{}
	deps.Registries = selectionTestFactory{inner: deps.Registries, err: want}
	deps.Runtime = selectionTestRuntime{deps.Runtime}
	app, err := application.New(deps)
	if err != nil {
		t.Fatal(err)
	}
	_, err = selectComposeRefs(context.Background(), app, &runOptions{composePlan: true}, []string{"registry.test/review/code:1.0.0"}, "", "", &out, &progress)
	var typed *selectionFactoryError
	if !errors.Is(err, want) || !errors.As(err, &typed) {
		t.Fatalf("lost typed registry error: %v", err)
	}
}

type selectionFactoryError struct{}

func (*selectionFactoryError) Error() string { return "registry authentication unavailable" }
