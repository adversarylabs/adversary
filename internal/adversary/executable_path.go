package adversary

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// executableFileInfo rejects symlinks in every existing pathname component.
// Execution still occurs later by pathname, so this is a cooperative same-user
// boundary rather than stable executable identity.
func executableFileInfo(path string) (fs.FileInfo, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	volume := filepath.VolumeName(abs)
	rel := strings.TrimPrefix(abs[len(volume):], string(filepath.Separator))
	current := volume + string(filepath.Separator)
	for _, component := range strings.Split(rel, string(filepath.Separator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("symlink component %q is not allowed", current)
		}
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file")
	}
	return info, nil
}
