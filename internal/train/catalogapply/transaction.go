package catalogapply

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

type catalogSnapshotEntry struct {
	mode fs.FileMode
	data []byte
	link string
}

type catalogTreeSnapshot struct {
	existed          bool
	mode             fs.FileMode
	entries          map[string]catalogSnapshotEntry
	linkTargetPath   string
	linkTargetExists bool
	linkTarget       catalogSnapshotEntry
}

func snapshotCatalogChange(adversaryDir, manifestPath string) (func() error, error) {
	tree, err := captureCatalogTree(adversaryDir)
	if err != nil {
		return nil, err
	}
	manifest, manifestErr := captureCatalogFile(manifestPath)
	if manifestErr != nil {
		return nil, manifestErr
	}
	return func() error {
		var restoreErr error
		if err := restoreCatalogTree(adversaryDir, tree); err != nil {
			restoreErr = fmt.Errorf("restore adversary after failed catalog apply: %w", err)
		}
		if err := restoreCatalogFile(manifestPath, manifest); err != nil && restoreErr == nil {
			restoreErr = fmt.Errorf("restore catalog manifest after failed apply: %w", err)
		}
		return restoreErr
	}, nil
}

func captureCatalogTree(root string) (catalogTreeSnapshot, error) {
	return captureCatalogTreeSkipping(root, nil)
}

func captureCatalogTreeSkipping(root string, skipDir func(string) bool) (catalogTreeSnapshot, error) {
	snapshot := catalogTreeSnapshot{entries: map[string]catalogSnapshotEntry{}}
	info, err := os.Lstat(root)
	if os.IsNotExist(err) {
		return snapshot, nil
	}
	if err != nil {
		return snapshot, err
	}
	if !info.IsDir() {
		return snapshot, fmt.Errorf("adversary path is not a directory: %s", root)
	}
	snapshot.existed = true
	snapshot.mode = info.Mode()
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, path)
		if err != nil || rel == "." {
			return err
		}
		if entry.IsDir() && skipDir != nil && skipDir(entry.Name()) {
			return filepath.SkipDir
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		item := catalogSnapshotEntry{mode: info.Mode()}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			item.link, err = os.Readlink(path)
		case info.IsDir():
		case info.Mode().IsRegular():
			item.data, err = os.ReadFile(path)
		default:
			return fmt.Errorf("unsupported catalog file type: %s", path)
		}
		if err == nil {
			snapshot.entries[filepath.ToSlash(rel)] = item
		}
		return err
	})
	return snapshot, err
}

func restoreCatalogTree(root string, snapshot catalogTreeSnapshot) error {
	if !snapshot.existed {
		return os.RemoveAll(root)
	}
	var current []string
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if os.IsNotExist(walkErr) {
			return nil
		}
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		current = append(current, path)
		return nil
	}); err != nil && !os.IsNotExist(err) {
		return err
	}
	sort.Slice(current, func(i, j int) bool { return len(current[i]) > len(current[j]) })
	for _, path := range current {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if err := os.MkdirAll(root, snapshot.mode.Perm()); err != nil {
		return err
	}
	if err := os.Chmod(root, snapshot.mode.Perm()); err != nil {
		return err
	}
	paths := make([]string, 0, len(snapshot.entries))
	for path := range snapshot.entries {
		paths = append(paths, path)
	}
	sort.Slice(paths, func(i, j int) bool { return len(paths[i]) < len(paths[j]) })
	for _, rel := range paths {
		entry := snapshot.entries[rel]
		path := filepath.Join(root, filepath.FromSlash(rel))
		switch {
		case entry.mode.IsDir():
			if err := os.MkdirAll(path, entry.mode.Perm()); err != nil {
				return err
			}
			if err := os.Chmod(path, entry.mode.Perm()); err != nil {
				return err
			}
		case entry.mode&os.ModeSymlink != 0:
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return err
			}
			if err := os.Symlink(entry.link, path); err != nil {
				return err
			}
		default:
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(path, entry.data, entry.mode.Perm()); err != nil {
				return err
			}
			if err := os.Chmod(path, entry.mode.Perm()); err != nil {
				return err
			}
		}
	}
	return nil
}

func captureCatalogFile(path string) (catalogTreeSnapshot, error) {
	snapshot := catalogTreeSnapshot{entries: map[string]catalogSnapshotEntry{}}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return snapshot, nil
	}
	if err != nil {
		return snapshot, err
	}
	snapshot.existed = true
	entry := catalogSnapshotEntry{mode: info.Mode()}
	if info.Mode()&os.ModeSymlink != 0 {
		entry.link, err = os.Readlink(path)
		if err == nil {
			resolved, resolveErr := filepath.EvalSymlinks(path)
			if resolveErr != nil {
				return snapshot, fmt.Errorf("resolve catalog manifest symlink: %w", resolveErr)
			}
			targetInfo, targetErr := os.Lstat(resolved)
			if targetErr != nil {
				return snapshot, fmt.Errorf("inspect catalog manifest symlink target: %w", targetErr)
			}
			if !targetInfo.Mode().IsRegular() {
				return snapshot, fmt.Errorf("catalog manifest symlink target is not a regular file: %s", resolved)
			}
			snapshot.linkTargetPath = resolved
			snapshot.linkTargetExists = true
			snapshot.linkTarget = catalogSnapshotEntry{mode: targetInfo.Mode()}
			snapshot.linkTarget.data, err = os.ReadFile(resolved)
		}
	} else if info.Mode().IsRegular() {
		entry.data, err = os.ReadFile(path)
	} else {
		return snapshot, fmt.Errorf("unsupported catalog manifest type: %s", path)
	}
	if err != nil {
		return snapshot, err
	}
	snapshot.entries["."] = entry
	return snapshot, nil
}

func restoreCatalogFile(path string, snapshot catalogTreeSnapshot) error {
	if !snapshot.existed {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	entry := snapshot.entries["."]
	if snapshot.linkTargetPath != "" {
		if !snapshot.linkTargetExists {
			if err := os.Remove(snapshot.linkTargetPath); err != nil && !os.IsNotExist(err) {
				return err
			}
		} else {
			if err := os.WriteFile(snapshot.linkTargetPath, snapshot.linkTarget.data, snapshot.linkTarget.mode.Perm()); err != nil {
				return err
			}
			if err := os.Chmod(snapshot.linkTargetPath, snapshot.linkTarget.mode.Perm()); err != nil {
				return err
			}
		}
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	if entry.mode&os.ModeSymlink != 0 {
		return os.Symlink(entry.link, path)
	}
	if err := os.WriteFile(path, entry.data, entry.mode.Perm()); err != nil {
		return err
	}
	return os.Chmod(path, entry.mode.Perm())
}
