package repopolicy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverCollectsScopedPolicyAndSiblingExamples(t *testing.T) {
	root := t.TempDir()
	write := func(path, content string) {
		t.Helper()
		full := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	write("AGENTS.md", "Use repository conventions.\n")
	write("src/AGENTS.md", "Use typed errors in this subtree.\n")
	write("src/changed.ts", "export const changed = true;\n")
	write("src/alpha.ts", "export const alpha = true;\n")
	write("src/bravo.ts", "export const bravo = true;\n")
	write("src/charlie.ts", "export const charlie = true;\n")
	write("src/ignored.go", "package ignored\n")

	context, err := Discover(root, []string{"src/changed.ts", "src/changed.ts", "../outside.ts"})
	if err != nil {
		t.Fatal(err)
	}
	if len(context.ExplicitSources) != 2 {
		t.Fatalf("explicit sources = %#v", context.ExplicitSources)
	}
	if context.ExplicitSources[0].Path != "AGENTS.md" || context.ExplicitSources[0].Scope != "" {
		t.Fatalf("root source = %#v", context.ExplicitSources[0])
	}
	if context.ExplicitSources[1].Path != "src/AGENTS.md" || context.ExplicitSources[1].Scope != "src" {
		t.Fatalf("scoped source = %#v", context.ExplicitSources[1])
	}
	if len(context.ChangedFiles) != 1 || len(context.ChangedFiles[0].Exemplars) != 3 {
		t.Fatalf("changed files = %#v", context.ChangedFiles)
	}
	for _, exemplar := range context.ChangedFiles[0].Exemplars {
		if filepath.Ext(exemplar.Path) != ".ts" || exemplar.Path == "src/changed.ts" {
			t.Fatalf("unexpected exemplar = %#v", exemplar)
		}
	}
}

func TestDiscoverDoesNotTreatOneExampleAsAConvention(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "changed.py"), []byte("changed = True\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "only.py"), []byte("only = True\n"), 0644); err != nil {
		t.Fatal(err)
	}
	context, err := Discover(root, []string{"changed.py"})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(context.ChangedFiles[0].Exemplars); got != 1 {
		t.Fatalf("exemplars = %d, want the available evidence preserved", got)
	}
	// The packet deliberately preserves available evidence; the broker prompt and
	// conventions specialist require three examples before calling it a convention.
}
