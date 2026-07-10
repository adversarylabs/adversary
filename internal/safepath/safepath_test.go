package safepath

import (
	"path/filepath"
	"testing"
)

func TestJoin(t *testing.T) {
	root := t.TempDir()
	for _, component := range []string{"", ".", "..", "../x", "a/b", `a\b`, "/tmp", `C:\tmp`, `C:tmp`, `\\server`, "nul\x00x", "x:y", "name.", "name ", "CON", "con.txt", "PRN", "aux.log", "NUL", "COM1", "com9.txt", "LPT1", "lpt9.log"} {
		t.Run(component, func(t *testing.T) {
			if _, err := Join(root, component); err == nil {
				t.Fatalf("Join accepted %q", component)
			}
		})
	}
	if rel, err := Relative("refs", "name", "latest"); err != nil || rel != "refs/name/latest" {
		t.Fatalf("Relative = %q, %v", rel, err)
	}
	got, err := Join(root, "sha256", "abc")
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Join(root, "sha256", "abc") {
		t.Fatalf("Join = %q", got)
	}
}

func FuzzJoin(f *testing.F) {
	for _, seed := range []string{"ok", "..", "a/b", `C:\x`, "e\u0301", "é", "x\x00y"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, component string) {
		path, err := Join(t.TempDir(), component)
		if err == nil && filepath.Base(path) != component {
			t.Fatalf("component changed: %q -> %q", component, path)
		}
	})
}
