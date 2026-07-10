// Package safepath constructs paths from validated, single-component names.
package safepath

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Join joins root and components after ensuring every component is a portable
// filename and that the result remains below root.
func Join(root string, components ...string) (string, error) {
	if root == "" {
		return "", fmt.Errorf("safe path root is required")
	}
	cleanRoot, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	path := cleanRoot
	for _, component := range components {
		if err := validateComponent(component); err != nil {
			return "", err
		}
		path = filepath.Join(path, component)
	}
	rel, err := filepath.Rel(cleanRoot, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("path escapes root")
	}
	return path, nil
}

func validateComponent(component string) error {
	if component == "" || component == "." || component == ".." {
		return fmt.Errorf("unsafe path component %q", component)
	}
	if strings.ContainsAny(component, "/\\\x00") || filepath.IsAbs(component) {
		return fmt.Errorf("unsafe path component %q", component)
	}
	// Reject Windows drive and UNC forms even when running on Unix.
	if len(component) >= 2 && ((component[0] >= 'A' && component[0] <= 'Z') || (component[0] >= 'a' && component[0] <= 'z')) && component[1] == ':' {
		return fmt.Errorf("unsafe path component %q", component)
	}
	if strings.HasPrefix(component, `\\`) {
		return fmt.Errorf("unsafe path component %q", component)
	}
	return nil
}
