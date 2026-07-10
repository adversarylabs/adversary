//go:build darwin

package archiveutil

import (
	"io/fs"
	"os"
)

func PreparePublish(root *os.Root) error {
	return fs.WalkDir(root.FS(), ".", func(path string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == "." {
			return root.Chmod(path, 0755)
		}
		info, err := e.Info()
		if err != nil {
			return err
		}
		if e.IsDir() {
			return root.Chmod(path, 0555)
		}
		return root.Chmod(path, info.Mode().Perm()&0111|0444)
	})
}
func ValidatePrepared(root *os.Root) error {
	info, err := root.Stat(".")
	if err != nil {
		return err
	}
	if info.Mode().Perm() != 0755 {
		return fs.ErrPermission
	}
	return validateChildren(root)
}
