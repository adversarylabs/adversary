package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// DataRoot returns the factory runtime data directory.
func DataRoot() string {
	if v := os.Getenv("FACTORY_DATA_ROOT"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", ".adversary-factory")
	}
	return filepath.Join(home, ".adversary-factory")
}

// EnsureDataRoot creates the standard layout under the data root.
func EnsureDataRoot(root string) error {
	dirs := []string{
		"mirrors/git",
		"github-cache",
		"objects/sha256",
		"bundles",
		"runs",
		"artifacts/adversaries",
		"worktrees",
		"reports",
		"experiments",
		"blocked",
		"state/discovery",
		"cases/discovery",
	}
	for _, d := range dirs {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", d, err)
		}
	}
	return nil
}

// RepoRoot finds the factory repository root (directory containing go.mod).
func RepoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found from %s", wd)
		}
		dir = parent
	}
}
