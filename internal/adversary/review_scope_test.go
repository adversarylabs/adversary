package adversary

import (
	"reflect"
	"testing"

	"github.com/adversarylabs/adversary/pkg/detection"
	"github.com/adversarylabs/adversary/pkg/manifest"
)

func TestScopeReviewContextKeepsOnlyRelevantChangedFiles(t *testing.T) {
	context := detection.Context{ChangedFiles: []detection.ChangedFile{
		{Path: "main.go", Status: detection.StatusModified},
		{Path: "web/app.ts", Status: detection.StatusModified},
		{Path: "README.md", Status: detection.StatusModified},
	}}
	m := manifest.Manifest{Detection: manifest.Detection{Files: []string{"**/*.go"}}}
	got, declared := ScopeReviewContext(m, context)
	if !declared {
		t.Fatal("scope was not declared")
	}
	want := []detection.ChangedFile{{Path: "main.go", Status: detection.StatusModified}}
	if !reflect.DeepEqual(got.ChangedFiles, want) {
		t.Fatalf("changed files = %#v, want %#v", got.ChangedFiles, want)
	}
	if len(context.ChangedFiles) != 3 {
		t.Fatal("input context was mutated")
	}
}

func TestScopeReviewContextLeavesGeneralistUnchanged(t *testing.T) {
	context := detection.Context{ChangedFiles: []detection.ChangedFile{{Path: "main.go"}, {Path: "README.md"}}}
	m := manifest.Manifest{Detection: manifest.Detection{Files: []string{"**/*"}}}
	got, declared := ScopeReviewContext(m, context)
	if !declared || !reflect.DeepEqual(got.ChangedFiles, context.ChangedFiles) {
		t.Fatalf("generalist scope = %#v, declared=%t", got.ChangedFiles, declared)
	}
}

func TestScopeReviewContextWithoutFileDetectionIsUnchanged(t *testing.T) {
	context := detection.Context{ChangedFiles: []detection.ChangedFile{{Path: "main.go"}}}
	got, declared := ScopeReviewContext(manifest.Manifest{}, context)
	if declared || !reflect.DeepEqual(got, context) {
		t.Fatalf("scope = %#v, declared=%t", got, declared)
	}
}
