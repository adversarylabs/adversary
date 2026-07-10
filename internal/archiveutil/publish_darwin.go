//go:build darwin

package archiveutil

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// PublishSealed atomically renames a sealed directory using no-follow parent
// descriptors. It returns true only when the destination was created.
func PublishSealed(base string, rooted *os.Root, from, to string) (bool, error) {
	srcParts, err := safeParts(from)
	if err != nil {
		return false, err
	}
	dstParts, err := safeParts(to)
	if err != nil {
		return false, err
	}
	root, err := unix.Open(base, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return false, err
	}
	defer unix.Close(root)
	srcParent, err := openParents(root, srcParts[:len(srcParts)-1])
	if err != nil {
		return false, err
	}
	defer unix.Close(srcParent)
	dstParent, err := openParents(root, dstParts[:len(dstParts)-1])
	if err != nil {
		return false, err
	}
	defer unix.Close(dstParent)
	stage, err := unix.Openat(srcParent, srcParts[len(srcParts)-1], unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return false, err
	}
	var before unix.Stat_t
	if err := unix.Fstat(stage, &before); err != nil {
		unix.Close(stage)
		return false, err
	}
	unix.Close(stage)
	if err := unix.RenameatxNp(srcParent, srcParts[len(srcParts)-1], dstParent, dstParts[len(dstParts)-1], unix.RENAME_EXCL); err != nil {
		return false, err
	}
	final, err := unix.Openat(dstParent, dstParts[len(dstParts)-1], unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return true, fmt.Errorf("open published directory: %w", err)
	}
	defer unix.Close(final)
	var after unix.Stat_t
	if err := unix.Fstat(final, &after); err != nil {
		return true, err
	}
	if before.Dev != after.Dev || before.Ino != after.Ino {
		return true, fmt.Errorf("published directory identity changed")
	}
	destRoot, err := rooted.OpenRoot(to)
	if err != nil {
		return true, err
	}
	sealErr := destRoot.Chmod(".", 0555)
	if sealErr == nil {
		sealErr = ValidateSealed(destRoot)
	}
	closeErr := destRoot.Close()
	if sealErr != nil {
		return true, sealErr
	}
	if closeErr != nil {
		return true, closeErr
	}
	return true, nil
}

func safeParts(path string) ([]string, error) {
	clean := filepath.ToSlash(filepath.Clean(path))
	if clean == "." || clean != path || strings.HasPrefix(clean, "/") {
		return nil, fmt.Errorf("unsafe publication path %q", path)
	}
	parts := strings.Split(clean, "/")
	for _, p := range parts {
		if p == "" || p == "." || p == ".." {
			return nil, fmt.Errorf("unsafe publication path %q", path)
		}
	}
	return parts, nil
}
func openParents(root int, parts []string) (int, error) {
	fd, err := unix.Dup(root)
	if err != nil {
		return -1, err
	}
	for _, part := range parts {
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		unix.Close(fd)
		if e != nil {
			return -1, e
		}
		fd = next
	}
	return fd, nil
}
