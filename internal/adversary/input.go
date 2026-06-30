package adversary

import "encoding/json"

const InputSchemaVersion = "adversary.input.v1"

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
	ChangedFiles []string `json:"changed_files"`
}

func NewInput(baseRef, headRef string, changedFiles []string) Input {
	input := Input{
		SchemaVersion: InputSchemaVersion,
		Source: InputSource{
			Path: "/workspace",
		},
	}
	if baseRef != "" && headRef != "" {
		input.Change = &InputChange{
			Type:         "diff",
			BaseRef:      baseRef,
			HeadRef:      headRef,
			ChangedFiles: changedFiles,
		}
	}
	return input
}

func MarshalInput(input Input) ([]byte, error) {
	return json.MarshalIndent(input, "", "  ")
}
