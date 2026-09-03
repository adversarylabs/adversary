// Package repopolicy discovers explicit repository guidance and representative
// source examples that model-backed adversaries can use as review context.
package repopolicy

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	maxSourceBytes = 12 << 10
	maxTotalBytes  = 96 << 10
	maxExamples    = 3
)

// Context is deliberately evidence, not a pre-interpreted list of rules. The
// reviewing model must distinguish an explicit instruction from a recurring
// implementation pattern and cite the repository source behind either one.
type Context struct {
	Version         int              `json:"version"`
	ExplicitSources []ExplicitSource `json:"explicitSources"`
	ChangedFiles    []ChangedFile    `json:"changedFiles"`
}

type ExplicitSource struct {
	Path      string `json:"path"`
	Scope     string `json:"scope"`
	Kind      string `json:"kind"`
	Content   string `json:"content"`
	Truncated bool   `json:"truncated,omitempty"`
}

type ChangedFile struct {
	Path      string     `json:"path"`
	Exemplars []Exemplar `json:"exemplars,omitempty"`
}

type Exemplar struct {
	Path      string `json:"path"`
	Reason    string `json:"reason"`
	Content   string `json:"content"`
	Truncated bool   `json:"truncated,omitempty"`
}

var explicitNames = map[string]string{
	"AGENTS.md":               "agent-instructions",
	"CONTRIBUTING":            "contributor-guide",
	"CONTRIBUTING.md":         "contributor-guide",
	"CONTRIBUTING.rst":        "contributor-guide",
	"STYLE.md":                "style-guide",
	"CODE_STYLE.md":           "style-guide",
	".editorconfig":           "editor-config",
	".clang-format":           "formatter-config",
	".swiftformat":            "formatter-config",
	".rubocop.yml":            "linter-config",
	".golangci.yml":           "linter-config",
	".golangci.yaml":          "linter-config",
	"ruff.toml":               "linter-config",
	"pyproject.toml":          "project-config",
	"eslint.config.js":        "linter-config",
	"eslint.config.mjs":       "linter-config",
	"eslint.config.cjs":       "linter-config",
	"eslint.config.ts":        "linter-config",
	".eslintrc":               "linter-config",
	".eslintrc.json":          "linter-config",
	".eslintrc.js":            "linter-config",
	".eslintrc.cjs":           "linter-config",
	".prettierrc":             "formatter-config",
	".prettierrc.json":        "formatter-config",
	"biome.json":              "formatter-config",
	"biome.jsonc":             "formatter-config",
	"deno.json":               "project-config",
	"deno.jsonc":              "project-config",
	"package.json":            "project-config",
	"tsconfig.json":           "project-config",
	"setup.cfg":               "project-config",
	"tox.ini":                 "test-config",
	"pytest.ini":              "test-config",
	"Cargo.toml":              "project-config",
	"go.mod":                  "project-config",
	"mix.exs":                 "project-config",
	"composer.json":           "project-config",
	"Makefile":                "build-policy",
	"prettier.config.js":      "formatter-config",
	"prettier.config.mjs":     "formatter-config",
	"rustfmt.toml":            "formatter-config",
	"Directory.Build.props":   "build-policy",
	"Directory.Build.targets": "build-policy",
}

// Discover returns a deterministic, bounded policy packet for the supplied
// changed paths. Explicit policy/config files are collected from repository
// root through each changed file's directory. Representative sibling source
// files provide evidence for conventions that are encoded only in existing
// code.
func Discover(root string, changedPaths []string) (Context, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return Context{}, fmt.Errorf("resolve repository root: %w", err)
	}
	context := Context{Version: 1, ExplicitSources: []ExplicitSource{}, ChangedFiles: []ChangedFile{}}
	paths := cleanChangedPaths(changedPaths)
	budget := maxTotalBytes

	policyPaths := policyCandidates(root, paths)
	for _, path := range policyPaths {
		if budget <= 0 {
			break
		}
		name := filepath.Base(path)
		kind, ok := explicitNames[name]
		if !ok {
			continue
		}
		content, truncated, readErr := readBounded(path, min(maxSourceBytes, budget))
		if readErr != nil {
			if os.IsNotExist(readErr) || errors.Is(readErr, fs.ErrInvalid) {
				continue
			}
			return Context{}, fmt.Errorf("read repository policy %s: %w", path, readErr)
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil || strings.HasPrefix(rel, "..") {
			continue
		}
		scope := filepath.ToSlash(filepath.Dir(rel))
		if scope == "." {
			scope = ""
		}
		context.ExplicitSources = append(context.ExplicitSources, ExplicitSource{
			Path: filepath.ToSlash(rel), Scope: scope, Kind: kind, Content: content, Truncated: truncated,
		})
		budget -= len(content)
	}

	for _, changedPath := range paths {
		item := ChangedFile{Path: changedPath, Exemplars: []Exemplar{}}
		if budget > 0 {
			examples, remaining, exampleErr := discoverExemplars(root, changedPath, budget)
			if exampleErr != nil {
				return Context{}, exampleErr
			}
			item.Exemplars = examples
			budget = remaining
		}
		context.ChangedFiles = append(context.ChangedFiles, item)
	}
	return context, nil
}

func cleanChangedPaths(paths []string) []string {
	seen := map[string]struct{}{}
	clean := make([]string, 0, len(paths))
	for _, path := range paths {
		path = filepath.ToSlash(filepath.Clean(strings.TrimSpace(path)))
		if path == "." || path == "" || strings.HasPrefix(path, "../") || filepath.IsAbs(path) {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		clean = append(clean, path)
	}
	sort.Strings(clean)
	return clean
}

func policyCandidates(root string, paths []string) []string {
	directories := map[string]struct{}{root: {}}
	for _, path := range paths {
		dir := filepath.Dir(filepath.Join(root, filepath.FromSlash(path)))
		for {
			if dir == root || strings.HasPrefix(dir, root+string(filepath.Separator)) {
				directories[dir] = struct{}{}
			}
			if dir == root {
				break
			}
			parent := filepath.Dir(dir)
			if parent == dir || !strings.HasPrefix(parent, root) {
				break
			}
			dir = parent
		}
	}
	dirs := make([]string, 0, len(directories))
	for dir := range directories {
		dirs = append(dirs, dir)
	}
	sort.Slice(dirs, func(i, j int) bool {
		depthI := strings.Count(strings.TrimPrefix(dirs[i], root), string(filepath.Separator))
		depthJ := strings.Count(strings.TrimPrefix(dirs[j], root), string(filepath.Separator))
		if depthI != depthJ {
			return depthI < depthJ
		}
		return dirs[i] < dirs[j]
	})
	names := make([]string, 0, len(explicitNames))
	for name := range explicitNames {
		names = append(names, name)
	}
	sort.Strings(names)
	result := make([]string, 0, len(dirs)*len(names))
	for _, dir := range dirs {
		for _, name := range names {
			result = append(result, filepath.Join(dir, name))
		}
	}
	return result
}

func discoverExemplars(root, changedPath string, budget int) ([]Exemplar, int, error) {
	changedOSPath := filepath.Join(root, filepath.FromSlash(changedPath))
	dir := filepath.Dir(changedOSPath)
	ext := filepath.Ext(changedOSPath)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, budget, nil
		}
		return nil, budget, fmt.Errorf("read sibling directory for %s: %w", changedPath, err)
	}
	type candidate struct {
		path   string
		reason string
		score  int
	}
	candidates := make([]candidate, 0, len(entries))
	stem := strings.TrimSuffix(filepath.Base(changedOSPath), ext)
	for _, entry := range entries {
		if entry.IsDir() || entry.Name() == filepath.Base(changedOSPath) || filepath.Ext(entry.Name()) != ext || ext == "" {
			continue
		}
		nameStem := strings.TrimSuffix(entry.Name(), ext)
		score := 1
		reason := "same-directory implementation with the same language"
		if isTestName(stem) == isTestName(nameStem) {
			score += 2
		}
		if strings.Contains(nameStem, stem) || strings.Contains(stem, nameStem) {
			score += 3
			reason = "closely named sibling implementation"
		}
		candidates = append(candidates, candidate{path: filepath.Join(dir, entry.Name()), reason: reason, score: score})
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].score != candidates[j].score {
			return candidates[i].score > candidates[j].score
		}
		return candidates[i].path < candidates[j].path
	})
	result := make([]Exemplar, 0, maxExamples)
	for _, candidate := range candidates {
		if len(result) == maxExamples || budget <= 0 {
			break
		}
		content, truncated, readErr := readBounded(candidate.path, min(maxSourceBytes, budget))
		if readErr != nil {
			continue
		}
		rel, relErr := filepath.Rel(root, candidate.path)
		if relErr != nil || strings.HasPrefix(rel, "..") {
			continue
		}
		result = append(result, Exemplar{Path: filepath.ToSlash(rel), Reason: candidate.reason, Content: content, Truncated: truncated})
		budget -= len(content)
	}
	return result, budget, nil
}

func readBounded(path string, limit int) (string, bool, error) {
	if limit <= 0 {
		return "", false, nil
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", false, fs.ErrInvalid
	}
	file, err := os.Open(path)
	if err != nil {
		return "", false, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, int64(limit+1)))
	if err != nil {
		return "", false, err
	}
	n := len(data)
	truncated := n > limit
	if truncated {
		n = limit
	}
	return string(data[:n]), truncated, nil
}

func isTestName(stem string) bool {
	lower := strings.ToLower(stem)
	return strings.Contains(lower, "test") || strings.Contains(lower, "spec")
}
