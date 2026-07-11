package manifest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"go.yaml.in/yaml/v3"
)

const valid = `name: adversarylabs/example
version: 1.2.3
triggers:
  manual: true
  files_changed: ["**/*.go"]
runtime:
  name: node
  version: "22"
  command: [dist/index.js]
permissions:
  filesystem:
    read: ["."]
    write: [.adversary/results]
  network: false
  env: [CI]
findings:
  format: adversary.review.v1
`

func TestParseValid(t *testing.T) {
	m, err := Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	if m.Name != "adversarylabs/example" || len(m.Runtime.Command) != 1 || m.Permissions.Network == nil || *m.Permissions.Network {
		t.Fatalf("unexpected manifest: %#v", m)
	}
}

func TestParseRejectsUnsafeAndInvalidInput(t *testing.T) {
	tests := map[string]string{
		"unknown field":      valid + "unknown: true\n",
		"duplicate":          strings.Replace(valid, "name: adversarylabs/example", "name: adversarylabs/example\nname: other/example", 1),
		"alias":              strings.Replace(valid, "command: [dist/index.js]", "command: &cmd [dist/index.js]", 1),
		"name":               strings.Replace(valid, "adversarylabs/example", "Adversary Labs/example", 1),
		"version":            strings.Replace(valid, "1.2.3", "latest", 1),
		"runtime":            strings.Replace(valid, "name: node", "name: shell", 1),
		"command":            strings.Replace(valid, "command: [dist/index.js]", "command: []", 1),
		"findings":           strings.Replace(valid, "adversary.review.v1", "sarif", 1),
		"env":                strings.Replace(valid, "env: [CI]", "env: [BAD-NAME]", 1),
		"path":               strings.Replace(valid, `read: ["."]`, `read: [""]`, 1),
		"absolute path":      strings.Replace(valid, `read: ["."]`, `read: ["/etc"]`, 1),
		"escaping path":      strings.Replace(valid, `read: ["."]`, `read: ["../secret"]`, 1),
		"duplicate path":     strings.Replace(valid, `write: [.adversary/results]`, `write: ["."]`, 1),
		"runtime constraint": strings.Replace(valid, `version: "22"`, `version: "latest"`, 1),
		"glob":               strings.Replace(valid, `files_changed: ["**/*.go"]`, `files_changed: [""]`, 1),
		"documents":          valid + "---\n" + valid,
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(input)); err == nil {
				t.Fatal("Parse succeeded")
			}
		})
	}
}

func TestValidateProjectChecksDeclaredRuntimeConsistency(t *testing.T) {
	dir := t.TempDir()
	m, err := Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.ValidateProject(dir); err == nil || !strings.Contains(err.Error(), "package.json") {
		t.Fatalf("error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.ValidateProject(dir); err != nil {
		t.Fatal(err)
	}
	m.Runtime.Command[0] = "bin/tool"
	if err := m.ValidateProject(dir); err == nil || !strings.Contains(err.Error(), "JavaScript") {
		t.Fatalf("error = %v", err)
	}
}

func TestNodeEntrypointMustRemainWithinProjectWithoutRequiringBuildOutput(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	m, err := Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	// dist/index.js deliberately does not exist: validation is lexical and must
	// support a source checkout before its build step.
	if err := m.ValidateProject(dir); err != nil {
		t.Fatalf("not-yet-built entrypoint rejected: %v", err)
	}
	for _, entrypoint := range []string{"../evil.js", "/tmp/evil.js", `..\evil.js`, `C:\evil.js`, "C:/evil.js", "dist/../evil.js"} {
		t.Run(entrypoint, func(t *testing.T) {
			input := strings.Replace(valid, "command: [dist/index.js]", fmt.Sprintf("command: [%q]", entrypoint), 1)
			if _, err := Parse([]byte(input)); err == nil {
				t.Fatal("Parse succeeded")
			}
		})
	}
}

func TestMalformedYAMLPolicyCorpus(t *testing.T) {
	for name, input := range map[string]string{
		"multiline scalar command": strings.Replace(valid, "command: [dist/index.js]", "command: [|\n      dist/index.js]", 1),
		"unicode confusable key":   strings.Replace(valid, "runtime:", "runtіme:", 1),
		"alias use":                strings.Replace(valid, "command: [dist/index.js]", "command: &command [dist/index.js]\n  image: *command", 1),
		"nested duplicate":         strings.Replace(valid, "manual: true", "manual: true\n  manual: false", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(input)); err == nil {
				t.Fatal("Parse succeeded")
			}
		})
	}
}

func TestParseSizeBound(t *testing.T) {
	if _, err := Parse(make([]byte, MaxSize+1)); err == nil {
		t.Fatal("Parse succeeded")
	}
}

func TestSemanticVersionParity(t *testing.T) {
	validVersions := []string{"0.0.0", "1.2.3", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-0A", "1.0.0+build.7", "1.0.0-beta+exp.sha"}
	invalidVersions := []string{"01.2.3", "1.02.3", "1.2.03", "1.2", "1.2.3-", "1.2.3-01", "1.2.3-alpha..1", "1.2.3+", "1.2.3+build..1"}
	for _, version := range validVersions {
		t.Run("valid/"+version, func(t *testing.T) {
			if _, err := Parse([]byte(strings.Replace(valid, "1.2.3", version, 1))); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, version := range invalidVersions {
		t.Run("invalid/"+version, func(t *testing.T) {
			if _, err := Parse([]byte(strings.Replace(valid, "1.2.3", version, 1))); err == nil {
				t.Fatal("Parse succeeded")
			}
		})
	}
}

func TestRuntimeImageStillValidatesOptionalFields(t *testing.T) {
	base := strings.Replace(valid, "  name: node\n  version: \"22\"", "  image: example.invalid/adversary:1", 1)
	if _, err := Parse([]byte(base)); err != nil {
		t.Fatal(err)
	}
	for name, replacement := range map[string]string{
		"name":        "  image: example.invalid/adversary:1\n  name: shell",
		"version":     "  image: example.invalid/adversary:1\n  version: \" 22\"",
		"empty image": "  image: \"\"",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(strings.Replace(base, "  image: example.invalid/adversary:1", replacement, 1))); err == nil {
				t.Fatal("Parse succeeded")
			}
		})
	}
}

func TestOptionalFieldsRejectPresentEmptyValues(t *testing.T) {
	for name, input := range map[string]string{
		"version":         strings.Replace(valid, "version: 1.2.3", `version: ""`, 1),
		"findings format": strings.Replace(valid, "format: adversary.review.v1", `format: ""`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(input)); err == nil {
				t.Fatal("Parse succeeded")
			}
		})
	}
}

func TestPublishedFixtures(t *testing.T) {
	validFixture, err := os.ReadFile(filepath.Join("..", "..", "schema", "fixtures", "adversary.manifest.v1.valid.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(validFixture); err != nil {
		t.Fatalf("valid fixture: %v", err)
	}
	invalidFixture, err := os.ReadFile(filepath.Join("..", "..", "schema", "fixtures", "adversary.manifest.v1.invalid.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(invalidFixture); err == nil {
		t.Fatal("invalid fixture parsed successfully")
	}
}

func TestPublishedDraft2020SchemaMatchesCanonicalFixtures(t *testing.T) {
	schemaData, err := os.ReadFile(filepath.Join("..", "..", "schema", "adversary.manifest.v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schemaDocument any
	if err := json.Unmarshal(schemaData, &schemaDocument); err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	const schemaURL = "https://adversary.dev/schemas/adversary.manifest.v1.schema.json"
	if err := compiler.AddResource(schemaURL, schemaDocument); err != nil {
		t.Fatal(err)
	}
	compiled, err := compiler.Compile(schemaURL)
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		input string
		valid bool
	}{
		"valid":               {valid, true},
		"unknown":             {valid + "unknown: true\n", false},
		"bad semver":          {strings.Replace(valid, "1.2.3", "1.2.3-01", 1), false},
		"unsupported runtime": {strings.Replace(valid, "name: node", "name: shell", 1), false},
		"empty command":       {strings.Replace(valid, "command: [dist/index.js]", "command: []", 1), false},
		"whitespace path":     {strings.Replace(valid, `read: ["."]`, `read: [" ."]`, 1), false},
		"absolute path":       {strings.Replace(valid, `read: ["."]`, `read: ["/etc"]`, 1), false},
		"traversal path":      {strings.Replace(valid, `read: ["."]`, `read: ["a/../secret"]`, 1), false},
		"backslash path":      {strings.Replace(valid, `read: ["."]`, `read: ["a\\\\secret"]`, 1), false},
		"drive path":          {strings.Replace(valid, `read: ["."]`, `read: ["C:/secret"]`, 1), false},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var document any
			if err := yaml.Unmarshal([]byte(tc.input), &document); err != nil {
				t.Fatal(err)
			}
			schemaErr := compiled.Validate(document)
			_, parseErr := Parse([]byte(tc.input))
			if tc.valid && (schemaErr != nil || parseErr != nil) {
				t.Fatalf("validity mismatch: schema=%v parser=%v", schemaErr, parseErr)
			}
			if !tc.valid && (schemaErr == nil || parseErr == nil) {
				t.Fatalf("invalid input accepted: schema=%v parser=%v", schemaErr, parseErr)
			}
		})
	}
}

func TestParserOnlySemanticRules(t *testing.T) {
	// These rules intentionally exceed JSON Schema's structural/syntactic
	// layer and are normative in Parse/Validate.
	for name, input := range map[string]string{
		"cross-array conflict":   strings.Replace(valid, `write: [.adversary/results]`, `write: ["."]`, 1),
		"full semver constraint": strings.Replace(valid, `version: "22"`, `version: "definitely-not-semver"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(input)); err == nil {
				t.Fatal("Parse succeeded")
			}
		})
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(valid))
	f.Add([]byte("x: &x [*x]"))
	f.Add([]byte("name: a\nname: b"))
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = Parse(data) })
}
