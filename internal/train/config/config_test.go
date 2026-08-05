package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDataRootAndEnsure(t *testing.T) {
	t.Setenv("FACTORY_DATA_ROOT", t.TempDir())
	root := DataRoot()
	if root == "" {
		t.Fatal("empty")
	}
	if err := EnsureDataRoot(root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "github-cache")); err != nil {
		t.Fatal(err)
	}
	// RepoRoot from cwd
	if _, err := RepoRoot(); err != nil {
		t.Log(err) // may fail if weird cwd
	}
}

func TestDataRootFallback(t *testing.T) {
	t.Setenv("FACTORY_DATA_ROOT", "")
	// just ensure non-empty
	if DataRoot() == "" {
		t.Fatal()
	}
}
