//go:build !windows

package rootreplace

import "os"

func mutable(root *os.Root, from, to string) error { return root.Rename(from, to) }
func syncDirectory(root *os.Root, path string) error {
	f, err := root.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
