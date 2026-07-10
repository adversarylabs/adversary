package rootreplace

import (
	"os"
	"path/filepath"
)

var SyncHook func(string) error

func SyncDirectory(root *os.Root, path string) error {
	if SyncHook != nil {
		if err := SyncHook("directory"); err != nil {
			return err
		}
	}
	return syncDirectory(root, path)
}

// Mutable atomically replaces an existing mutable index while keeping both
// paths constrained to root.
func Mutable(root *os.Root, from, to string) error {
	if err := syncFile(root, from); err != nil {
		return err
	}
	if err := mutable(root, from, to); err != nil {
		return err
	}
	return syncParents(root, from, to)
}

// Immutable publishes without replacing an existing object.
func Immutable(root *os.Root, from, to string) error {
	if err := syncFile(root, from); err != nil {
		return err
	}
	if err := root.Link(from, to); err != nil {
		return err
	}
	if err := syncParents(root, from, to); err != nil {
		return err
	}
	if err := root.Remove(from); err != nil {
		return err
	}
	return syncParents(root, from, to)
}
func syncFile(root *os.Root, path string) error {
	if SyncHook != nil {
		if err := SyncHook("file"); err != nil {
			return err
		}
	}
	f, err := root.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func syncParents(root *os.Root, paths ...string) error {
	seen := map[string]bool{}
	for _, p := range paths {
		dir := filepath.ToSlash(filepath.Dir(p))
		if seen[dir] {
			continue
		}
		seen[dir] = true
		if err := SyncDirectory(root, dir); err != nil {
			return err
		}
	}
	return nil
}
