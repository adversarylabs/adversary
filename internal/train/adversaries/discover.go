package adversaries

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/adversarylabs/adversary/internal/train/scope"
	"gopkg.in/yaml.v3"
)

// Package is a sibling adversary checkout the factory can route to / run.
type Package struct {
	// Dir is absolute path to the adversary package root.
	Dir string
	// DirName is the folder name, e.g. go-concurrency-adversary.
	DirName string
	// ID is a short stable id, e.g. go-concurrency.
	ID string
	// ManifestName from adversary.yaml name field, e.g. go/concurrency.
	ManifestName string
	// Description from adversary.yaml.
	Description string
	// ScopeMarkdown from docs/scope.md.
	ScopeMarkdown string
	// ScopePath filesystem path to scope.md.
	ScopePath string
	// Languages inferred from triggers/files (go, typescript, …) or "any".
	Languages []string
	// FileGlobs from triggers.files_changed.
	FileGlobs []string
}

// DiscoverSiblings finds *-adversary directories next to factoryRoot's parent
// (…/adversarylabs/adversary-factory → …/adversarylabs/*-adversary).
func DiscoverSiblings(factoryRoot string) ([]Package, error) {
	abs, err := filepath.Abs(factoryRoot)
	if err != nil {
		return nil, err
	}
	parent := filepath.Dir(abs)
	entries, err := os.ReadDir(parent)
	if err != nil {
		return nil, err
	}
	var out []Package
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, "-adversary") {
			continue
		}
		dir := filepath.Join(parent, name)
		pkg, err := loadPackage(dir, name)
		if err != nil {
			// Skip packages without scope.md — not ready for routing.
			continue
		}
		out = append(out, pkg)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	if len(out) == 0 {
		return nil, fmt.Errorf("no sibling *-adversary packages with docs/scope.md under %s", parent)
	}
	return out, nil
}

func loadPackage(dir, dirName string) (Package, error) {
	scopeText, scopePath, err := scope.LoadMissionFromAdversary(dir)
	if err != nil {
		return Package{}, err
	}
	id := strings.TrimSuffix(dirName, "-adversary")
	pkg := Package{
		Dir:           dir,
		DirName:       dirName,
		ID:            id,
		ScopeMarkdown: scopeText,
		ScopePath:     scopePath,
		Languages:     []string{"any"},
	}
	// Parse adversary.yaml for name/description/globs.
	raw, err := os.ReadFile(filepath.Join(dir, "adversary.yaml"))
	if err == nil {
		var y struct {
			Name        string `yaml:"name"`
			Description string `yaml:"description"`
			Triggers    struct {
				FilesChanged []string `yaml:"files_changed"`
			} `yaml:"triggers"`
			Detection struct {
				Files []string `yaml:"files"`
			} `yaml:"detection"`
		}
		if yaml.Unmarshal(raw, &y) == nil {
			pkg.ManifestName = y.Name
			pkg.Description = y.Description
			pkg.FileGlobs = y.Triggers.FilesChanged
			if len(pkg.FileGlobs) == 0 {
				pkg.FileGlobs = y.Detection.Files
			}
			pkg.Languages = languagesFromGlobs(pkg.FileGlobs, id)
		}
	}
	if pkg.ManifestName == "" {
		pkg.ManifestName = id
	}
	return pkg, nil
}

func languagesFromGlobs(globs []string, id string) []string {
	seen := map[string]bool{}
	for _, g := range globs {
		g = strings.ToLower(g)
		switch {
		case strings.Contains(g, ".go"):
			seen["go"] = true
		case strings.Contains(g, ".ts") || strings.Contains(g, ".tsx"):
			seen["typescript"] = true
		case strings.Contains(g, ".js") || strings.Contains(g, ".jsx"):
			seen["javascript"] = true
		case strings.Contains(g, ".py"):
			seen["python"] = true
		case strings.Contains(g, ".rs"):
			seen["rust"] = true
		case strings.Contains(g, ".java"):
			seen["java"] = true
		case strings.Contains(g, "workflow") || strings.Contains(g, ".github"):
			seen["ci"] = true
		case strings.Contains(g, "dockerfile"):
			seen["dockerfile"] = true
		case strings.Contains(g, "terraform") || strings.Contains(g, ".tf"):
			seen["terraform"] = true
		}
	}
	// id hints
	id = strings.ToLower(id)
	if strings.HasPrefix(id, "go") {
		seen["go"] = true
	}
	if strings.Contains(id, "typescript") || strings.Contains(id, "react") || strings.Contains(id, "next") {
		seen["typescript"] = true
	}
	if strings.Contains(id, "python") {
		seen["python"] = true
	}
	if strings.Contains(id, "githubactions") || strings.Contains(id, "gitlabci") || strings.Contains(id, "depotci") {
		seen["ci"] = true
	}
	if strings.Contains(id, "engineering-review") || strings.Contains(id, "complexity") || strings.Contains(id, "secrets") {
		return []string{"any"}
	}
	if len(seen) == 0 {
		return []string{"any"}
	}
	var out []string
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ByID indexes packages by short id.
func ByID(pkgs []Package) map[string]Package {
	m := map[string]Package{}
	for _, p := range pkgs {
		m[p.ID] = p
	}
	return m
}
