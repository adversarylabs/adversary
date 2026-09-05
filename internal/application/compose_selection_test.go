package application

import (
	"context"
	"github.com/adversarylabs/adversary/pkg/detection"
	"github.com/adversarylabs/adversary/pkg/manifest"
	"reflect"
	"testing"
)

func TestPlanComposeFiltersMetadataWithoutPruningChildren(t *testing.T) {
	packages := map[string]ComposeMetadata{
		"root":      {Manifest: manifest.Manifest{Name: "root", Version: "1", Uses: []manifest.Use{{Name: "python", Version: "1"}, {Name: "go", Version: "1"}}}},
		"python:1":  {Manifest: manifest.Manifest{Name: "python", Version: "1", Detection: manifest.Detection{Files: []string{"**/*.py"}}, Uses: []manifest.Use{{Name: "general", Version: "1"}}}},
		"go:1":      {Reference: "registry.test/go@sha256:pinned", Manifest: manifest.Manifest{Name: "go", Version: "1", Detection: manifest.Detection{Files: []string{"**/*.go"}}}},
		"general:1": {Manifest: manifest.Manifest{Name: "general", Version: "1"}},
	}
	var batches [][]string
	loader := func(_ context.Context, refs []string) map[string]ComposeMetadata {
		batches = append(batches, refs)
		out := map[string]ComposeMetadata{}
		for _, ref := range refs {
			out[ref] = packages[ref]
		}
		return out
	}
	plan, err := PlanCompose(context.Background(), []string{"root"}, loader, &detection.Context{RepositoryFiles: []string{"main.go"}})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plan.Refs, []string{"root", "registry.test/go@sha256:pinned", "general:1"}) {
		t.Fatalf("refs: %v", plan.Refs)
	}
	if len(batches) != 3 || len(batches[1]) != 2 {
		t.Fatalf("not batched: %v", batches)
	}
	if plan.Selections[1].Selected {
		t.Fatal("python was selected")
	}
}
func TestPlanComposeExplicitRootOverridesGate(t *testing.T) {
	plan, err := PlanCompose(context.Background(), []string{"python"}, func(_ context.Context, refs []string) map[string]ComposeMetadata {
		return map[string]ComposeMetadata{"python": {Manifest: manifest.Manifest{Name: "python", Version: "1", Detection: manifest.Detection{Files: []string{"**/*.py"}}}}}
	}, &detection.Context{RepositoryFiles: []string{"main.go"}})
	if err != nil || len(plan.Refs) != 1 {
		t.Fatalf("%+v %v", plan, err)
	}
}
func TestPlanComposeMissingMetadataRetained(t *testing.T) {
	plan, err := PlanCompose(context.Background(), []string{"missing"}, func(context.Context, []string) map[string]ComposeMetadata { return nil }, nil)
	if err != nil || len(plan.Refs) != 1 {
		t.Fatalf("%+v %v", plan, err)
	}
}
