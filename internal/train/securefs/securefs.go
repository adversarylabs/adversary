// Package securefs writes train state with user-only permissions.
// Live collection stores private PR/review content; world-readable modes
// would leak that to other local accounts on a shared machine.
package securefs

import (
	"os"
	"path/filepath"
)

// Directory and file modes for train state (github-cache, cases, runs, etc.).
const (
	DirMode  = 0o700
	FileMode = 0o600
)

// MkdirAll creates path and parents with DirMode (0700).
// Existing directories that are still world-accessible are chmod'd to DirMode when
// we can (stops quietly on permission errors higher in the tree, e.g. /tmp).
func MkdirAll(path string) error {
	if err := os.MkdirAll(path, DirMode); err != nil {
		return err
	}
	tightenDirChain(path)
	return nil
}

// WriteFile writes data with FileMode (0600), creating parents as needed.
// Always chmod's the file after write so overwriting a 0644 file becomes 0600.
func WriteFile(path string, data []byte) error {
	if err := MkdirAll(filepath.Dir(path)); err != nil {
		return err
	}
	if err := os.WriteFile(path, data, FileMode); err != nil {
		return err
	}
	// os.WriteFile does not change mode of an existing file — force 0600.
	return os.Chmod(path, FileMode)
}

// tightenDirChain chmods path and walkable parents while world-accessible.
// Chmod errors on system parents are ignored (we still secured what we own).
func tightenDirChain(path string) {
	cur, err := filepath.Abs(path)
	if err != nil {
		cur = path
	}
	for i := 0; i < 16; i++ {
		st, err := os.Lstat(cur)
		if err != nil {
			return
		}
		if st.IsDir() && st.Mode().Perm()&0o077 != 0 {
			if err := os.Chmod(cur, DirMode); err != nil {
				// Cannot tighten further up (e.g. /var/folders) — done.
				return
			}
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return
		}
		cur = parent
	}
}
