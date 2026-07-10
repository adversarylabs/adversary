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
		if dirs[i] == "." {
			continue
		}
		if err := root.Chmod(dirs[i], 0755); err != nil {
			return err
		}
	}
	return nil
}

var DefaultLimits = Limits{CompressedBytes: 256 << 20, ExpandedBytes: 1 << 30, FileBytes: 256 << 20, Files: 10000, PathBytes: 4096, CompressionRatio: 100}

// ExtractGzipTar extracts a deliberately small tar subset: directories and
// regular files. It rejects links, devices, sparse entries, duplicate paths and
// archive amplification before publishing any content outside root.
func ExtractGzipTar(src io.Reader, root *os.Root, limits Limits) error {
	compressed := &countingReader{r: io.LimitReader(src, limits.CompressedBytes+1)}
	gz, err := gzip.NewReader(compressed)
	if err != nil {
		return err
	}
	defer gz.Close()
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
			if compressed.n > 0 && expanded > compressed.n*limits.CompressionRatio {
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
	if compressed.n > limits.CompressedBytes {
		return fmt.Errorf("archive exceeds compressed size limit")
	}
	return nil
}

type countingReader struct {
	r io.Reader
	n int64
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.n += int64(n)
	return n, err
}
