package review

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestErrorEnvelopeFixtureAndCanonicalEncoding(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "schema", "fixtures", "adversary.error.v1.valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := DecodeErrorEnvelope(data)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeErrorEnvelope(envelope.Error)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `{"error":{"code":"invalid_manifest","details":{"field":"runtime.version"},"message":"runtime.version is not a valid constraint","retryable":false},"protocolVersion":1}`+"\n" {
		t.Fatalf("encoding = %s", encoded)
	}
}

func TestErrorEnvelopeRejectsNewerAndMalformedVersions(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "schema", "fixtures", "adversary.error.v1.invalid.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name     string          `json:"name"`
		Envelope json.RawMessage `json:"envelope"`
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		if _, err := DecodeErrorEnvelope(tc.Envelope); err == nil {
			t.Fatalf("accepted %s: %s", tc.Name, tc.Envelope)
		}
	}
}

func TestErrorSchemaIsPublishedAndValidJSON(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "schema", "adversary.error.v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	vendored, err := os.ReadFile(filepath.Join("..", "..", "templates", "typescript", "vendor", "adversary-sdk", "schemas", "adversary.error.v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(data)) != strings.TrimSpace(string(vendored)) {
		t.Fatal("vendored error schema diverges")
	}
	var fixture any
	fixtureData, err := os.ReadFile(filepath.Join("..", "..", "schema", "fixtures", "adversary.error.v1.valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(fixtureData, &fixture); err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	const schemaURL = "https://adversary.dev/schemas/adversary.error.v1.schema.json"
	if err := compiler.AddResource(schemaURL, document); err != nil {
		t.Fatal(err)
	}
	compiled, err := compiler.Compile(schemaURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := compiled.Validate(fixture); err != nil {
		t.Fatal(err)
	}
	invalidData, err := os.ReadFile(filepath.Join("..", "..", "schema", "fixtures", "adversary.error.v1.invalid.json"))
	if err != nil {
		t.Fatal(err)
	}
	var invalid []struct {
		Name     string `json:"name"`
		Envelope any    `json:"envelope"`
	}
	if err := json.Unmarshal(invalidData, &invalid); err != nil {
		t.Fatal(err)
	}
	for _, tc := range invalid {
		if err := compiled.Validate(tc.Envelope); err == nil {
			t.Fatalf("schema accepted %s", tc.Name)
		}
	}
}
