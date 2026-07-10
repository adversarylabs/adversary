// Package safepath constructs paths from validated, single-component names.
package safepath

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

var windowsDevice = regexp.MustCompile(`(?i)^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$`)

// Relative returns a slash-separated path made only from portable validated
// components, suitable for descriptor-backed os.Root operations.
func Relative(components ...string) (string, error) {
	for _, component := range components {
		if err := validateComponent(component); err != nil {
			return "", err
		}
	}
	return strings.Join(components, "/"), nil
}

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
	relative, err := Relative(components...)
	if err != nil {
		return "", err
	}
	path := filepath.Join(cleanRoot, filepath.FromSlash(relative))
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
	if strings.ContainsAny(component, "/\\:\x00") || filepath.IsAbs(component) {
		return fmt.Errorf("unsafe path component %q", component)
	}
	if strings.HasSuffix(component, ".") || strings.HasSuffix(component, " ") || windowsDevice.MatchString(component) {
		return fmt.Errorf("unsafe portable path component %q", component)
	}
	// Reject Windows drive and UNC forms even when running on Unix.
	if strings.HasPrefix(component, `\\`) {
		return fmt.Errorf("unsafe path component %q", component)
	}
	return nil
}
