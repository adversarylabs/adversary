package adversary

import (
	"os"
	"path/filepath"

	internalpaths "github.com/adversarylabs/adversary/internal/paths"
	"github.com/adversarylabs/adversary/pkg/repository"
)

// DefaultResolver is the concrete process-filesystem factory used only at the
// command composition edge. Resolver operations themselves use RuntimeFiles.
func DefaultResolver() (Resolver, error) {
	dataRoot, err := resolverDataRoot()
	if err != nil {
		return Resolver{}, err
	}
	root := filepath.Join(dataRoot, "repository-v1")
	if err := os.MkdirAll(root, 0700); err != nil {
		return Resolver{}, err
	}
	repo := repository.Repository{Root: root}
	if entries, readErr := os.ReadDir(filepath.Join(root, "transactions")); readErr == nil && len(entries) > 0 {
		if err := repo.Recover(); err != nil {
			return Resolver{}, err
		}
	} else if readErr != nil && !os.IsNotExist(readErr) {
		return Resolver{}, readErr
	}
	return Resolver{Repository: repo, Files: OSRuntimeFiles{}}, nil
}

func resolverDataRoot() (string, error) {
	return internalpaths.DataDir()
}
