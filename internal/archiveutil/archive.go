package archiveutil

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/adversarylabs/adversary/internal/safepath"
)

type Limits struct {
	CompressedBytes  int64
	ExpandedBytes    int64
	FileBytes        int64
	Files            int
	PathBytes        int
	CompressionRatio int64
}

// Seal removes write bits after all preparation is complete. Directories are
// processed last so their children remain reachable during the operation.
func Seal(root *os.Root) error {
	var dirs []string
	err := fs.WalkDir(root.FS(), ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if entry.IsDir() {
			dirs = append(dirs, path)
			return nil
		}
		return root.Chmod(path, info.Mode().Perm()&0111|0444)
	})
	if err != nil {
		return err
	}
	for i := len(dirs) - 1; i >= 0; i-- {
		if err := root.Chmod(dirs[i], 0555); err != nil {
			return err
		}
	}
	return nil
}

func Unseal(root *os.Root) error {
	var dirs []string
	err := fs.WalkDir(root.FS(), ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if entry.IsDir() {
			dirs = append(dirs, path)
			return root.Chmod(path, 0755)
		}
		return root.Chmod(path, info.Mode().Perm()&0111|0644)
	})
	return err
}

var DefaultLimits = Limits{CompressedBytes: 256 << 20, ExpandedBytes: 1 << 30, FileBytes: 256 << 20, Files: 10000, PathBytes: 4096, CompressionRatio: 100}

// ExtractGzipTar extracts a deliberately small tar subset: directories and
// regular files. It rejects links, devices, sparse entries, duplicate paths and
// archive amplification before publishing any content outside root.
func ExtractGzipTar(src io.Reader, root *os.Root, limits Limits) error {
	if limits.CompressedBytes <= 0 || limits.ExpandedBytes <= 0 || limits.FileBytes <= 0 || limits.Files <= 0 || limits.PathBytes <= 0 || limits.CompressionRatio <= 0 {
		return fmt.Errorf("archive limits must all be positive")
	}
	spool, err := os.CreateTemp("", "adversary-archive-*")
	if err != nil {
		return err
	}
	name := spool.Name()
	defer os.Remove(name)
	defer spool.Close()
	n, err := io.CopyBuffer(spool, io.LimitReader(src, limits.CompressedBytes+1), make([]byte, 32<<10))
	if err != nil {
		return err
	}
	if n > limits.CompressedBytes {
		return fmt.Errorf("archive exceeds compressed size limit")
	}
	if _, err := spool.Seek(0, io.SeekStart); err != nil {
		return err
	}
	gz, err := gzip.NewReader(spool)
	if err != nil {
		return err
	}
	gz.Multistream(false)
	tr := tar.NewReader(gz)
	seen := map[string]byte{}
	var expanded int64
	for count := 0; ; count++ {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if count >= limits.Files {
			return fmt.Errorf("archive exceeds file count limit %d", limits.Files)
		}
		if len(h.Name) > limits.PathBytes {
			return fmt.Errorf("archive path exceeds limit: %q", h.Name)
		}
		clean := filepath.ToSlash(filepath.Clean(h.Name))
		rel, pathErr := safepath.Relative(strings.Split(clean, "/")...)
		if pathErr != nil || clean == "." || clean != h.Name {
			return fmt.Errorf("unsafe package path %q", h.Name)
		}
		kind := byte('f')
		if h.Typeflag == tar.TypeDir {
			kind = 'd'
		}
		if old, ok := seen[rel]; ok {
			return fmt.Errorf("duplicate archive path %q (types %c and %c)", rel, old, kind)
		}
		seen[rel] = kind
		switch h.Typeflag {
		case tar.TypeDir:
			if err := root.MkdirAll(rel, 0755); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if h.Size < 0 || h.Size > limits.FileBytes {
				return fmt.Errorf("archive file %q exceeds size limit", h.Name)
			}
			expanded += h.Size
			if expanded > limits.ExpandedBytes {
				return fmt.Errorf("archive exceeds expanded size limit")
			}
			if expanded > n*limits.CompressionRatio {
				return fmt.Errorf("archive exceeds compression ratio limit")
			}
			if err := root.MkdirAll(filepath.ToSlash(filepath.Dir(rel)), 0755); err != nil {
				return err
			}
			f, err := root.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, os.FileMode(h.Mode)&0111|0444)
			if err != nil {
				return err
			}
			n, copyErr := io.CopyBuffer(f, io.LimitReader(tr, h.Size), make([]byte, 32<<10))
			closeErr := f.Close()
			if copyErr != nil {
				return copyErr
			}
			if n != h.Size {
				return fmt.Errorf("archive file %q was truncated", h.Name)
			}
			if closeErr != nil {
				return closeErr
			}
		default:
			return fmt.Errorf("unsupported archive entry type %d for %q", h.Typeflag, h.Name)
		}
	}
	if _, err := io.CopyBuffer(io.Discard, gz, make([]byte, 32<<10)); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	return nil
}
