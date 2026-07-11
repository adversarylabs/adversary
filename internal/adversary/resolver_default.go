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
	return Resolver{Repository: repository.Repository{Root: root}, Files: OSRuntimeFiles{}}, nil
}

func resolverDataRoot() (string, error) {
	return internalpaths.DataDir()
}
