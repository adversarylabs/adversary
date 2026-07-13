package pack

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDecodeArtifactConfigStrictJSONAndInventory(t *testing.T) {
	valid := ArtifactConfig{
		Created: "1970-01-01T00:00:00Z", Name: "tool", FullName: "team/tool", Version: "1.0.0",
		Runtime: "typescript", RuntimeName: "node", RuntimeVersion: "22", Entrypoint: []string{"index.js"},
		Files: []File{{Path: "index.js", Size: 1, SHA256: strings.Repeat("0", 64), Mode: 0o644}},
	}
	validData, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		data []byte
	}{
		{"unknown field", append(validData[:len(validData)-1], []byte(`,"unknown":true}`)...)},
		{"duplicate top-level", []byte(`{"created":"1970-01-01T00:00:00Z","created":"later","files":[]}`)},
		{"duplicate nested", []byte(`{"created":"1970-01-01T00:00:00Z","name":"tool","full_name":"team/tool","version":"1.0.0","runtime":"custom","entrypoint":["tool"],"files":[{"path":"tool","path":"other","size":1,"sha256":"` + strings.Repeat("0", 64) + `","mode":420}]}`)},
		{"trailing value", append(validData, []byte(` {}`)...)},
		{"missing inventory", []byte(`{"created":"1970-01-01T00:00:00Z"}`)},
		{"duplicate inventory path", []byte(`{"created":"1970-01-01T00:00:00Z","files":[{"path":"a","size":1,"sha256":"` + strings.Repeat("0", 64) + `","mode":420},{"path":"a","size":1,"sha256":"` + strings.Repeat("0", 64) + `","mode":420}]}`)},
	}
	if _, err := DecodeArtifactConfig(validData); err != nil {
		t.Fatalf("valid config: %v", err)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := DecodeArtifactConfig(test.data); err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
}
