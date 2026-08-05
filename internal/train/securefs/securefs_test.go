package securefs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileUserOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "secret.json")
	if err := WriteFile(path, []byte(`{"private":true}`)); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		t.Fatalf("file should not be group/other readable: %o", st.Mode().Perm())
	}
	parent, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if parent.Mode().Perm()&0o077 != 0 {
		t.Fatalf("dir should not be group/other accessible: %o", parent.Mode().Perm())
	}
}

func TestWriteFileTightensExistingWorldReadable(t *testing.T) {
	dir := t.TempDir()
	// Pre-create world-readable tree (legacy train state).
	sub := filepath.Join(dir, "github-cache")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(sub, "pull.json")
	if err := os.WriteFile(path, []byte(`old`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(path, []byte(`new private`)); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != FileMode {
		t.Fatalf("want %#o after overwrite, got %#o", FileMode, st.Mode().Perm())
	}
	// Dir should be tightened when we MkdirAll through WriteFile parents.
	dst, err := os.Stat(sub)
	if err != nil {
		t.Fatal(err)
	}
	if dst.Mode().Perm()&0o077 != 0 {
		t.Fatalf("dir still world-accessible: %#o", dst.Mode().Perm())
	}
	raw, _ := os.ReadFile(path)
	if string(raw) != "new private" {
		t.Fatalf("content %q", raw)
	}
}
