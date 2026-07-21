package detection

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestConfidenceOrdering(t *testing.T) {
	if ConfidenceHigh.Rank() <= ConfidenceMedium.Rank() || ConfidenceMedium.Rank() <= ConfidenceLow.Rank() {
		t.Fatal("confidence ranks are not high > medium > low")
	}
	if _, err := ParseConfidence("unknown"); err == nil {
		t.Fatal("ParseConfidence accepted an unknown value")
	}
}

func TestPublishedSchemasAcceptCanonicalContracts(t *testing.T) {
	context := Context{SchemaVersion: SchemaVersion, RepositoryRoot: "/workspace", Mode: ModeDirtyWorktree, ChangedFiles: []ChangedFile{{Path: "Dockerfile", Status: StatusModified}}}
	result := Result{SchemaVersion: SchemaVersion, Applicable: true, Confidence: ConfidenceHigh, Reasons: []string{"Dockerfile changed"}, RelevantFiles: []string{"Dockerfile"}}
	for _, tc := range []struct {
		file  string
		value any
	}{
		{"adversary.detection-context.v1.schema.json", context},
		{"adversary.detection.v1.schema.json", result},
	} {
		data, err := os.ReadFile(filepath.Join("..", "..", "schema", tc.file))
		if err != nil {
			t.Fatal(err)
		}
		compiler := jsonschema.NewCompiler()
		compiler.DefaultDraft(jsonschema.Draft2020)
		var document any
		if err := json.Unmarshal(data, &document); err != nil {
			t.Fatal(err)
		}
		if err := compiler.AddResource("schema.json", document); err != nil {
			t.Fatal(err)
		}
		schema, err := compiler.Compile("schema.json")
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(tc.value)
		if err != nil {
			t.Fatal(err)
		}
		var instance any
		if err := json.Unmarshal(encoded, &instance); err != nil {
			t.Fatal(err)
		}
		if err := schema.Validate(instance); err != nil {
			t.Fatalf("%s rejected canonical contract: %v", tc.file, err)
		}
	}
}

func TestVendoredTypeScriptSchemasMatchCanonical(t *testing.T) {
	for _, name := range []string{"adversary.detection-context.v1.schema.json", "adversary.detection.v1.schema.json"} {
		canonical, err := os.ReadFile(filepath.Join("..", "..", "schema", name))
		if err != nil {
			t.Fatal(err)
		}
		for _, root := range []string{
			filepath.Join("..", "..", "templates", "typescript", "vendor", "adversary-sdk", "schemas"),
			filepath.Join("..", "..", "smoke-tests", "comment-sentence-adversary", "vendor", "adversary-sdk", "schemas"),
		} {
			vendored, err := os.ReadFile(filepath.Join(root, name))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(vendored, canonical) {
				t.Fatalf("%s is not synchronized with %s", filepath.Join(root, name), name)
			}
		}
	}
}

func TestResultValidationAndNormalization(t *testing.T) {
	result := Result{SchemaVersion: SchemaVersion, Applicable: true, Confidence: ConfidenceHigh, Reasons: []string{"Dockerfile changed", "Dockerfile changed"}, RelevantFiles: []string{"z", "a", "a"}}
	if err := result.Validate(); err != nil {
		t.Fatal(err)
	}
	result.Normalize()
	if !reflect.DeepEqual(result.Reasons, []string{"Dockerfile changed"}) || !reflect.DeepEqual(result.RelevantFiles, []string{"a", "z"}) {
		t.Fatalf("normalized result = %#v", result)
	}
}

func TestResultRequiresVersionConfidenceAndReason(t *testing.T) {
	for _, result := range []Result{
		{Confidence: ConfidenceHigh, Reasons: []string{"match"}},
		{SchemaVersion: SchemaVersion, Confidence: "certain", Reasons: []string{"match"}},
		{SchemaVersion: SchemaVersion, Confidence: ConfidenceHigh},
	} {
		if err := result.Validate(); err == nil {
			t.Fatalf("Validate accepted %#v", result)
		}
	}
}
