package adversary

import (
	"encoding/json"
	"testing"
)

func TestMarshalInputPlainRepo(t *testing.T) {
	data, err := MarshalInput(NewInput("", "", nil))
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

func TestMarshalInputDiff(t *testing.T) {
	data, err := MarshalInput(NewInput("main", "HEAD", []string{".github/workflows/test.yml"}))
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
	if len(got.Change.ChangedFiles) != 1 || got.Change.ChangedFiles[0] != ".github/workflows/test.yml" {
		t.Fatalf("ChangedFiles = %#v", got.Change.ChangedFiles)
	}
}
