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
