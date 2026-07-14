package archiveutil

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func FuzzExtractGzipTar(f *testing.F) {
	valid, err := archiveFuzzSeed("safe/file.txt", []byte("content"))
	if err != nil {
		f.Fatal(err)
	}
	traversal, err := archiveFuzzSeed("../escape", []byte("content"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add(traversal)
	f.Add([]byte("not gzip"))
	f.Add(valid[:len(valid)/2])
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			data = data[:64<<10]
		}
		parent, err := os.MkdirTemp("", "adversary-archive-fuzz-*")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(parent)
		rootPath := filepath.Join(parent, "root")
		if err := os.Mkdir(rootPath, 0o700); err != nil {
			t.Fatal(err)
		}
		sentinel := filepath.Join(parent, "sentinel")
		if err := os.WriteFile(sentinel, []byte("unchanged"), 0o600); err != nil {
			t.Fatal(err)
		}
		root, err := os.OpenRoot(rootPath)
		if err != nil {
			t.Fatal(err)
		}
		limits := Limits{CompressedBytes: 64 << 10, ExpandedBytes: 256 << 10, FileBytes: 64 << 10, Files: 64, PathBytes: 512, CompressionRatio: 100}
		extractErr := ExtractGzipTar(bytes.NewReader(data), root, limits)
		if err := root.Close(); err != nil {
			t.Fatal(err)
		}
		content, err := os.ReadFile(sentinel)
		if err != nil || string(content) != "unchanged" {
			t.Fatalf("archive escaped extraction root: content=%q err=%v", content, err)
		}
		if err := filepath.WalkDir(parent, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(parent, path)
			if err != nil || rel == ".." || filepath.IsAbs(rel) {
				t.Fatalf("path escaped fuzz parent: path=%q rel=%q err=%v", path, rel, err)
			}
			insideRoot := rel == "root" || len(rel) > len("root") && rel[:len("root")+1] == "root"+string(filepath.Separator)
			if rel != "." && rel != "sentinel" && !insideRoot {
				t.Fatalf("archive created sibling outside extraction root: %q", rel)
			}
			if insideRoot && entry.Type()&os.ModeSymlink != 0 {
				t.Fatalf("extractor produced symlink %q", path)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if extractErr != nil {
			return
		}
	})
}

func archiveFuzzSeed(name string, body []byte) ([]byte, error) {
	var output bytes.Buffer
	gz := gzip.NewWriter(&output)
	tarWriter := tar.NewWriter(gz)
	if err := tarWriter.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))}); err != nil {
		return nil, err
	}
	if _, err := tarWriter.Write(body); err != nil {
		return nil, err
	}
	if err := tarWriter.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}
