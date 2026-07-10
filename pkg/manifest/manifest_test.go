package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
		"unknown field": valid + "unknown: true\n",
		"duplicate":     strings.Replace(valid, "name: adversarylabs/example", "name: adversarylabs/example\nname: other/example", 1),
		"alias":         strings.Replace(valid, "command: [dist/index.js]", "command: &cmd [dist/index.js]", 1),
		"name":          strings.Replace(valid, "adversarylabs/example", "Adversary Labs/example", 1),
		"version":       strings.Replace(valid, "1.2.3", "latest", 1),
		"runtime":       strings.Replace(valid, "name: node", "name: shell", 1),
		"command":       strings.Replace(valid, "command: [dist/index.js]", "command: []", 1),
		"findings":      strings.Replace(valid, "adversary.review.v1", "sarif", 1),
		"env":           strings.Replace(valid, "env: [CI]", "env: [BAD-NAME]", 1),
		"path":          strings.Replace(valid, `read: ["."]`, `read: [""]`, 1),
		"glob":          strings.Replace(valid, `files_changed: ["**/*.go"]`, `files_changed: [""]`, 1),
		"documents":     valid + "---\n" + valid,
	}
	for name, input := range tests {
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

func FuzzParse(f *testing.F) {
	f.Add([]byte(valid))
	f.Add([]byte("x: &x [*x]"))
	f.Add([]byte("name: a\nname: b"))
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = Parse(data) })
}
