package adversary

import (
	"encoding/json"

	"github.com/adversarylabs/adversary/pkg/detection"
)

const InputSchemaVersion = "adversary.input.v1"

const (
	WorktreeInputBaseRef = "HEAD"
	WorktreeInputHeadRef = "WORKTREE"
)

type Input struct {
	SchemaVersion string       `json:"schema_version"`
	Source        InputSource  `json:"source"`
	Change        *InputChange `json:"change"`
}

type InputSource struct {
	Path string `json:"path"`
}

type InputChange struct {
	Type         string   `json:"type"`
	BaseRef      string   `json:"base_ref"`
	HeadRef      string   `json:"head_ref"`
	ScanMode     string   `json:"scan_mode"`
	ChangedFiles []string `json:"changed_files"`
}

func NewInput(baseRef, headRef string, changedFiles []string, allFiles bool) Input {
	input := Input{
		SchemaVersion: InputSchemaVersion,
		Source: InputSource{
			Path: "/workspace",
		},
	}
	if baseRef != "" && headRef != "" {
		scanMode := "changed"
		if allFiles {
			scanMode = "all"
		}
		input.Change = &InputChange{
			Type:         "diff",
			BaseRef:      baseRef,
			HeadRef:      headRef,
			ScanMode:     scanMode,
			ChangedFiles: changedFiles,
		}
	}
	return input
}

// NewInputFromReviewContext preserves the v1 runtime input for existing
// adversaries while also representing dirty-worktree paths. WORKTREE is a
// stable sentinel, not a Git revision; the authoritative structured context is
// provided separately through ADVERSARY_CHANGE_CONTEXT.
func NewInputFromReviewContext(context detection.Context, allFiles bool) Input {
	baseRef, headRef := context.BaseRef, context.HeadRef
	if context.Mode == detection.ModeDirtyWorktree {
		baseRef, headRef = WorktreeInputBaseRef, WorktreeInputHeadRef
	}
	changedFiles := make([]string, 0, len(context.ChangedFiles))
	for _, changed := range context.ChangedFiles {
		changedFiles = append(changedFiles, changed.Path)
	}
	return NewInput(baseRef, headRef, changedFiles, allFiles)
}

func MarshalInput(input Input) ([]byte, error) {
	return json.MarshalIndent(input, "", "  ")
}
