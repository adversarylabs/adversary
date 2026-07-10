package archiveutil

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"strings"
	"testing"
)

type testEntry struct {
	name string
	kind byte
	body string
}

func testArchive(t *testing.T, entries ...testEntry) []byte {
	t.Helper()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Typeflag: e.kind, Mode: 0644, Size: int64(len(e.body))}
		if e.kind == tar.TypeSymlink {
			h.Linkname, h.Size = "../outside", 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if e.kind == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func testExtract(t *testing.T, data []byte, limits Limits) error {
	t.Helper()
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	return ExtractGzipTar(bytes.NewReader(data), root, limits)
}

func TestRejectsMaliciousArchives(t *testing.T) {
	base := Limits{CompressedBytes: 1 << 20, ExpandedBytes: 1 << 20, FileBytes: 1 << 20, Files: 10, PathBytes: 100, CompressionRatio: 1000}
	tests := []struct {
		name   string
		data   []byte
		mutate func(*Limits)
	}{
		{"traversal", testArchive(t, testEntry{"../escape", tar.TypeReg, "x"}), nil},
		{"symlink", testArchive(t, testEntry{"link", tar.TypeSymlink, ""}), nil},
		{"duplicate", testArchive(t, testEntry{"x", tar.TypeReg, "x"}, testEntry{"x", tar.TypeReg, "y"}), nil},
		{"type conflict", testArchive(t, testEntry{"x", tar.TypeDir, ""}, testEntry{"x", tar.TypeReg, "y"}), nil},
		{"file size", testArchive(t, testEntry{"x", tar.TypeReg, "xx"}), func(l *Limits) { l.FileBytes = 1 }},
		{"total size", testArchive(t, testEntry{"x", tar.TypeReg, "xx"}), func(l *Limits) { l.ExpandedBytes = 1 }},
		{"path", testArchive(t, testEntry{strings.Repeat("x", 20), tar.TypeReg, "x"}), func(l *Limits) { l.PathBytes = 10 }},
		{"count", testArchive(t, testEntry{"x", tar.TypeReg, "x"}, testEntry{"y", tar.TypeReg, "y"}), func(l *Limits) { l.Files = 1 }},
		{"ratio", testArchive(t, testEntry{"x", tar.TypeReg, strings.Repeat("x", 10000)}), func(l *Limits) { l.CompressionRatio = 2 }},
		{"compressed", testArchive(t, testEntry{"x", tar.TypeReg, "x"}), func(l *Limits) { l.CompressedBytes = 10 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := base
			if tt.mutate != nil {
				tt.mutate(&l)
			}
			if err := testExtract(t, tt.data, l); err == nil {
				t.Fatal("malicious archive accepted")
			}
		})
	}
}

func TestPreservesExecutableMode(t *testing.T) {
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	body := []byte("#!/bin/sh\n")
	if err := tw.WriteHeader(&tar.Header{Name: "run.sh", Typeflag: tar.TypeReg, Mode: 0755, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := ExtractGzipTar(bytes.NewReader(b.Bytes()), root, DefaultLimits); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir + "/run.sh")
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0555 {
		t.Fatalf("mode=%o", info.Mode().Perm())
	}
}

func TestCompressedLimitCountsTrailingData(t *testing.T) {
	data := testArchive(t, testEntry{"x", tar.TypeReg, "x"})
	limit := int64(len(data))
	data = append(data, bytes.Repeat([]byte("z"), 32)...)
	l := DefaultLimits
	l.CompressedBytes = limit
	if err := testExtract(t, data, l); err == nil {
		t.Fatal("trailing bytes bypassed compressed limit")
	}
}

func TestRejectsBadGzipChecksum(t *testing.T) {
	data := testArchive(t, testEntry{"x", tar.TypeReg, "x"})
	data[len(data)-5] ^= 0xff
	if err := testExtract(t, data, DefaultLimits); err == nil {
		t.Fatal("bad gzip checksum accepted")
	}
}
