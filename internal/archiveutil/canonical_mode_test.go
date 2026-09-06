package archiveutil

import (
	"os"
	"path/filepath"
	"testing"
)

// Emulate modes produced by restrictive process masks without changing the
// process mask or weakening the immutable publication validator.
func TestCanonicalPublicationModes(t *testing.T) {
	for _, mode := range []os.FileMode{0400, 0444, 0500, 0544, 0550, 0555} {
		for _, prepare := range []bool{false, true} {
			dir := t.TempDir()
			name := filepath.Join(dir, "entry")
			if err := os.WriteFile(name, []byte("unchanged payload"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(name, mode); err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			if prepare {
				err = PreparePublish(root)
			} else {
				err = Seal(root)
			}
			if err != nil {
				t.Fatal(err)
			}
			if prepare {
				err = ValidatePrepared(root)
			} else {
				err = ValidateSealed(root)
			}
			if err != nil {
				t.Errorf("mode %o prepare %v: %v", mode, prepare, err)
			}
			data, err := os.ReadFile(name)
			if err != nil || string(data) != "unchanged payload" {
				t.Fatal("content changed", err)
			}
			info, err := os.Stat(name)
			if err != nil {
				t.Fatal(err)
			}
			want := os.FileMode(0444)
			if mode&0111 != 0 {
				want = 0555
			}
			if info.Mode().Perm() != want {
				t.Errorf("got %o want %o", info.Mode().Perm(), want)
			}
			root.Close()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
		}
	}
}
