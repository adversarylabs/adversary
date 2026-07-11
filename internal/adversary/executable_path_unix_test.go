//go:build !windows

package adversary

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeNodeCandidate(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\nprintf 'v22.4.0\\n'\n"), mode); err != nil {
		t.Fatal(err)
	}
}

func isolatedNodeSearch(t *testing.T, path string) {
	t.Helper()
	t.Setenv("PATH", path)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("ADVERSARY_NODE_PATH", "")
}

func realTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestFindNodeValidatesPATHCandidate(t *testing.T) {
	bin := realTempDir(t)
	writeNodeCandidate(t, filepath.Join(bin, "node"), 0755)
	isolatedNodeSearch(t, bin)
	got, err := findNode("22")
	if err != nil || got != filepath.Join(bin, "node") {
		t.Fatalf("findNode = %q, %v", got, err)
	}
}

func TestFindNodeRejectsNonExecutablePATHCandidate(t *testing.T) {
	bin := realTempDir(t)
	writeNodeCandidate(t, filepath.Join(bin, "node"), 0644)
	isolatedNodeSearch(t, bin)
	if got, err := findNode("22"); err == nil || got != "" {
		t.Fatalf("findNode = %q, %v", got, err)
	}
}

func TestExecutableCandidateRejectsDirectoryAndSymlinks(t *testing.T) {
	root := realTempDir(t)
	if err := os.Mkdir(filepath.Join(root, "directory"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := validateExecutable(filepath.Join(root, "directory")); err == nil || !strings.Contains(err.Error(), "regular") {
		t.Fatalf("directory error = %v", err)
	}
	target := filepath.Join(root, "node-real")
	writeNodeCandidate(t, target, 0755)
	link := filepath.Join(root, "node-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := validateExecutable(link); err == nil || !strings.Contains(err.Error(), "symlink component") {
		t.Fatalf("final symlink error = %v", err)
	}
	parentLink := filepath.Join(realTempDir(t), "bin-link")
	if err := os.Symlink(root, parentLink); err != nil {
		t.Fatal(err)
	}
	if err := validateExecutable(filepath.Join(parentLink, "node-real")); err == nil || !strings.Contains(err.Error(), "symlink component") {
		t.Fatalf("parent symlink error = %v", err)
	}
}

func TestFindNodeRejectsSymlinkPATHCandidate(t *testing.T) {
	bin := realTempDir(t)
	target := filepath.Join(realTempDir(t), "node-real")
	writeNodeCandidate(t, target, 0755)
	if err := os.Symlink(target, filepath.Join(bin, "node")); err != nil {
		t.Fatal(err)
	}
	isolatedNodeSearch(t, bin)
	if got, err := findNode("22"); err == nil || got != "" {
		t.Fatalf("findNode = %q, %v", got, err)
	}
}
