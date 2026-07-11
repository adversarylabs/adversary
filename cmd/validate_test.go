package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateCommandTextAndJSON(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"adversary.yaml", "package.json"} {
		data, err := os.ReadFile(filepath.Join("..", "templates", "typescript", name))
		if err != nil {
			t.Fatal(err)
		}
		data = bytes.ReplaceAll(data, []byte("{{name}}"), []byte("validation-test"))
		data = bytes.ReplaceAll(data, []byte("{{version}}"), []byte("0.1.0"))
		data = bytes.ReplaceAll(data, []byte("{{description}}"), []byte("test"))
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, format := range []string{"text", "json"} {
		var out bytes.Buffer
		command := NewRootCommand(&out, &out)
		command.SetArgs([]string{"validate", dir, "--format", format})
		if err := command.Execute(); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "adversary.manifest.v1") {
			t.Fatalf("output = %s", out.String())
		}
	}
}

func TestValidateCommandJSONFailureIsVersionedAndActionable(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "adversary.yaml"), []byte("name: BAD\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	command := NewRootCommand(&out, &out)
	command.SetArgs([]string{"validate", dir, "--format", "json"})
	if err := command.Execute(); err == nil {
		t.Fatal("validate succeeded")
	}
	for _, want := range []string{`"schemaVersion":1`, `"command":"validate"`, `"status":"invalid"`, `"code":"invalid_manifest"`, `"manifestVersion":"adversary.manifest.v1"`} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output missing %s: %s", want, out.String())
		}
	}
}
