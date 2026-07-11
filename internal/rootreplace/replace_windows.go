//go:build windows

package rootreplace

import (
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"strings"
)

func mutable(root *os.Root, from, to string) error {
	from, err := safe(from)
	if err != nil {
		return err
	}
	to, err = safe(to)
	if err != nil {
		return err
	}
	for _, p := range []string{filepath.Dir(from), filepath.Dir(to)} {
		d, err := root.OpenRoot(p)
		if err != nil {
			return err
		}
		if err := d.Close(); err != nil {
			return err
		}
	}
	src, err := windows.UTF16PtrFromString(filepath.Join(root.Name(), filepath.FromSlash(from)))
	if err != nil {
		return err
	}
	dst, err := windows.UTF16PtrFromString(filepath.Join(root.Name(), filepath.FromSlash(to)))
	if err != nil {
		return err
	}
	return windows.MoveFileEx(src, dst, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
func safe(p string) (string, error) {
	clean := filepath.ToSlash(filepath.Clean(p))
	if clean == "." || clean != p || strings.HasPrefix(clean, "/") || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("unsafe rooted replacement path %q", p)
	}
	return clean, nil
}

// MoveFileEx WRITE_THROUGH flushes the move; directory FlushFileBuffers is not
// consistently supported on Windows, so this additional sync is best effort.
func syncDirectory(root *os.Root, path string) error {
	f, err := root.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_ = f.Sync()
	return nil
}
