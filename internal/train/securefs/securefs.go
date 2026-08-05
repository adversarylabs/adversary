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
func MkdirAll(path string) error {
	return os.MkdirAll(path, DirMode)
}

// WriteFile writes data with FileMode (0600), creating parents as needed.
func WriteFile(path string, data []byte) error {
	if err := MkdirAll(filepath.Dir(path)); err != nil {
		return err
	}
	return os.WriteFile(path, data, FileMode)
}
