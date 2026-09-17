package adversary

import (
	"encoding/json"
	"testing"

	"github.com/adversarylabs/adversary/pkg/detection"
)

func TestMarshalInputPlainRepo(t *testing.T) {
	data, err := MarshalInput(NewInput("", "", nil, false))
	if err != nil {
		t.Fatal(err)
	}

	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got["schema_version"] != "adversary.input.v1" {
		t.Fatalf("schema_version = %v", got["schema_version"])
	}
	if got["change"] != nil {
		t.Fatalf("change = %#v", got["change"])
	}
	source := got["source"].(map[string]any)
	if source["path"] != "/workspace" {
		t.Fatalf("source.path = %v", source["path"])
	}
}

func TestNewInputFromDirtyReviewContextPreservesChangedFiles(t *testing.T) {
	input := NewInputFromReviewContext(detection.Context{Mode: detection.ModeDirtyWorktree, ChangedFiles: []detection.ChangedFile{{Path: "staged.go", Status: detection.StatusModified}, {Path: "new.go", Status: detection.StatusUntracked}}}, false)
	if input.Change == nil {
		t.Fatal("Change is nil")
	}
	if input.Change.BaseRef != WorktreeInputBaseRef || input.Change.HeadRef != WorktreeInputHeadRef {
		t.Fatalf("worktree refs = %q...%q", input.Change.BaseRef, input.Change.HeadRef)
	}
	if len(input.Change.ChangedFiles) != 2 || input.Change.ChangedFiles[0] != "staged.go" || input.Change.ChangedFiles[1] != "new.go" {
		t.Fatalf("ChangedFiles = %#v", input.Change.ChangedFiles)
	}
}

func TestNewInputFromReviewContextUsesResolvedMergeBase(t *testing.T) {
	input := NewInputFromReviewContext(detection.Context{
		Mode:      detection.ModePullRequest,
		BaseRef:   "main",
		HeadRef:   "deadbeef",
		MergeBase: "cafebabe",
		ChangedFiles: []detection.ChangedFile{
			{Path: "src/app.ts", Status: detection.StatusModified},
		},
	}, false)
	if input.Change == nil {
		t.Fatal("Change is nil")
	}
	if input.Change.BaseRef != "cafebabe" || input.Change.HeadRef != "deadbeef" {
		t.Fatalf("resolved refs = %q...%q", input.Change.BaseRef, input.Change.HeadRef)
	}
}

func TestMarshalInputDiff(t *testing.T) {
	data, err := MarshalInput(NewInput("main", "HEAD", []string{".github/workflows/test.yml"}, false))
	if err != nil {
		t.Fatal(err)
	}

	var got Input
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Change == nil {
		t.Fatal("Change is nil")
	}
	if got.Change.Type != "diff" || got.Change.BaseRef != "main" || got.Change.HeadRef != "HEAD" {
		t.Fatalf("Change = %#v", got.Change)
	}
	if got.Change.ScanMode != "changed" {
		t.Fatalf("ScanMode = %q", got.Change.ScanMode)
	}
	if len(got.Change.ChangedFiles) != 1 || got.Change.ChangedFiles[0] != ".github/workflows/test.yml" {
		t.Fatalf("ChangedFiles = %#v", got.Change.ChangedFiles)
	}
}

func TestMarshalInputDiffAllFiles(t *testing.T) {
	data, err := MarshalInput(NewInput("main", "HEAD", []string{"README.md"}, true))
	if err != nil {
		t.Fatal(err)
	}

	var got Input
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Change == nil {
		t.Fatal("Change is nil")
	}
	if got.Change.ScanMode != "all" {
		t.Fatalf("ScanMode = %q", got.Change.ScanMode)
	}
	if len(got.Change.ChangedFiles) != 1 || got.Change.ChangedFiles[0] != "README.md" {
		t.Fatalf("ChangedFiles = %#v", got.Change.ChangedFiles)
	}
}

func TestWithChangedRanges(t *testing.T) {
	input := NewInputFromReviewContext(detection.Context{
		Mode:         detection.ModeBranchComparison,
		BaseRef:      "main",
		HeadRef:      "HEAD",
		ChangedFiles: []detection.ChangedFile{{Path: "src/app.ts", Status: detection.StatusModified}},
	}, false).WithChangedRanges([]detection.ReviewRegion{{Path: "src/app.ts", StartLine: 12, EndLine: 18}})

	data, err := MarshalInput(input)
	if err != nil {
		t.Fatal(err)
	}
	var got Input
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Change == nil || len(got.Change.ChangedRanges) != 1 {
		t.Fatalf("ChangedRanges = %#v", got.Change)
	}
	want := detection.ReviewRegion{Path: "src/app.ts", StartLine: 12, EndLine: 18}
	if got.Change.ChangedRanges[0] != want {
		t.Fatalf("ChangedRanges[0] = %#v, want %#v", got.Change.ChangedRanges[0], want)
	}
}
