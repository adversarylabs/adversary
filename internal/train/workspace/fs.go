package workspace

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/adversarylabs/adversary/internal/train/securefs"
)

// EnsureStateDir creates the state directory tree (user-only 0700).
func EnsureStateDir(path string) error {
	return securefs.MkdirAll(path)
}

// ReadFile reads a file from disk.
func ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// WriteFile writes a file to disk (user-only 0600 for train state).
func WriteFile(path string, data []byte) error {
	return securefs.WriteFile(path, data)
}

// WorkingDir returns the process working directory.
func WorkingDir() (string, error) {
	return os.Getwd()
}

// ResolveStateAbs joins workspace config dir with relative state dir.
func ResolveStateAbs(cfgPath, stateDir string) string {
	if filepath.IsAbs(stateDir) {
		return stateDir
	}
	return filepath.Join(filepath.Dir(cfgPath), stateDir)
}

// DirExists reports whether path is a directory.
func DirExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.IsDir()
}

// FileExists reports whether path is a regular file.
func FileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

// ListDir names of children.
func ListDir(path string) ([]string, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names, nil
}

// FindSuggestedIssues looks under stateRoot for SUGGESTED_ISSUES.md.
func FindSuggestedIssues(stateRoot string) (string, []byte, error) {
	candidates := []string{
		filepath.Join(stateRoot, "LATEST_SUGGESTED_ISSUES.md"),
		filepath.Join(stateRoot, "SUGGESTED_ISSUES.md"),
	}
	if entries, err := os.ReadDir(filepath.Join(stateRoot, "experiments")); err == nil {
		for i := len(entries) - 1; i >= 0; i-- {
			if entries[i].IsDir() {
				candidates = append([]string{filepath.Join(stateRoot, "experiments", entries[i].Name(), "SUGGESTED_ISSUES.md")}, candidates...)
				break
			}
		}
	}
	for _, c := range candidates {
		raw, err := os.ReadFile(c)
		if err == nil {
			return c, raw, nil
		}
	}
	return "", nil, fmt.Errorf("no suggested issues found under %s", stateRoot)
}

// RewriteTrainDrafts updates suggested-issue files under stateRoot for train branding.
func RewriteTrainDrafts(stateRoot string) error {
	return filepath.Walk(stateRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		if info.Name() != "SUGGESTED_ISSUES.md" {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		text := string(raw)
		text = strings.ReplaceAll(text, "adversary-factory discovery", "adversary train")
		text = strings.ReplaceAll(text, "Drafted by adversary-factory", "Drafted by adversary train")
		return os.WriteFile(path, []byte(text), 0o644)
	})
}

// FirstScopedPackage returns the first child of root with a scope.md
// (agent/scope.md preferred; train/ and docs/ accepted).
func FirstScopedPackage(root string) string {
	entries, err := os.ReadDir(root)
	if err != nil {
		return root
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		cand := filepath.Join(root, e.Name())
		if hasScopeMarkdown(cand) {
			return cand
		}
	}
	return root
}

func hasScopeMarkdown(pkgRoot string) bool {
	for _, rel := range []string{
		filepath.Join("agent", "scope.md"),
		filepath.Join("train", "scope.md"),
		filepath.Join("docs", "scope.md"),
	} {
		if FileExists(filepath.Join(pkgRoot, rel)) {
			return true
		}
	}
	return false
}

// FindTrainFixturesRoot locates internal/train containing fixtures/cases.
func FindTrainFixturesRoot(start string) string {
	dir := start
	for {
		cand := filepath.Join(dir, "internal", "train")
		if DirExists(filepath.Join(cand, "fixtures", "cases")) {
			return cand
		}
		if DirExists(filepath.Join(dir, "fixtures", "cases")) {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return start
}
