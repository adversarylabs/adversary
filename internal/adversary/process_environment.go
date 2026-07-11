package adversary

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

var ErrUnsafeCapturedPATH = errors.New("captured PATH contains an empty or relative entry")

// ProcessEnvironment is an immutable, normalized snapshot. On Windows keys
// are case-insensitive; the last occurrence wins on every platform.
type ProcessEnvironment struct {
	values  map[string]string
	keys    map[string]string
	windows bool
}

func NewProcessEnvironment(entries []string, windows bool) ProcessEnvironment {
	e := ProcessEnvironment{values: map[string]string{}, keys: map[string]string{}, windows: windows}
	for _, entry := range entries {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || key == "" {
			continue
		}
		normalized := e.normalize(key)
		e.values[normalized] = value
		e.keys[normalized] = key
	}
	return e
}

func (e ProcessEnvironment) normalize(key string) string {
	if e.windows {
		return strings.ToUpper(key)
	}
	return key
}
func (e ProcessEnvironment) Lookup(key string) (string, bool) {
	v, ok := e.values[e.normalize(key)]
	return v, ok
}
func (e ProcessEnvironment) Entries(overrides map[string]string) []string {
	values := make(map[string]string, len(e.values)+len(overrides))
	keys := make(map[string]string, len(e.keys)+len(overrides))
	for key, value := range e.values {
		values[key], keys[key] = value, e.keys[key]
	}
	for key, value := range overrides {
		normalized := e.normalize(key)
		values[normalized], keys[normalized] = value, key
	}
	normalized := make([]string, 0, len(values))
	for key := range values {
		normalized = append(normalized, key)
	}
	sort.Strings(normalized)
	result := make([]string, 0, len(normalized))
	for _, key := range normalized {
		result = append(result, keys[key]+"="+values[key])
	}
	return result
}
func (e ProcessEnvironment) LookPath(file string, resolve func(string) (string, error)) (string, error) {
	if resolve == nil {
		return "", fmt.Errorf("executable resolver dependency is required")
	}
	if strings.ContainsAny(file, `/\\`) {
		resolved, err := resolve(file)
		if err != nil {
			return "", err
		}
		if !filepath.IsAbs(resolved) {
			return "", fmt.Errorf("resolved executable %q is not absolute", resolved)
		}
		return filepath.Clean(resolved), nil
	}
	path, hasPath := e.Lookup("PATH")
	if hasPath && path == "" {
		return "", fmt.Errorf("%w: %q", ErrUnsafeCapturedPATH, path)
	}
	dirs := filepath.SplitList(path)
	for _, dir := range dirs {
		if dir == "" || !filepath.IsAbs(dir) {
			return "", fmt.Errorf("%w: %q", ErrUnsafeCapturedPATH, dir)
		}
	}
	for _, dir := range dirs {
		candidate := filepath.Join(dir, file)
		if e.windows && filepath.Ext(candidate) == "" {
			pathext, _ := e.Lookup("PATHEXT")
			if strings.TrimSpace(pathext) == "" {
				pathext = ".COM;.EXE;.BAT;.CMD"
			}
			for _, ext := range strings.Split(pathext, ";") {
				withExt := candidate + strings.TrimSpace(ext)
				if resolved, err := resolve(withExt); err == nil {
					if !filepath.IsAbs(resolved) {
						return "", fmt.Errorf("resolved executable %q is not absolute", resolved)
					}
					return filepath.Clean(resolved), nil
				}
			}
		}
		if resolved, err := resolve(candidate); err == nil {
			if !filepath.IsAbs(resolved) {
				return "", fmt.Errorf("resolved executable %q is not absolute", resolved)
			}
			return filepath.Clean(resolved), nil
		}
	}
	return "", fmt.Errorf("executable %q was not found in captured PATH", file)
}
