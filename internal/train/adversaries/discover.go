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
	// ScopeMarkdown from agent/scope.md (or train/docs legacy paths).
	ScopeMarkdown string
	// ScopePath filesystem path to scope.md.
	ScopePath string
	// Languages inferred from triggers/files (go, typescript, …) or "any".
	Languages []string
	// FileGlobs from triggers.files_changed.
	FileGlobs []string
	// Uses are composition members from adversary.yaml (name/version or path).
	// Always expanded when this local package is run for train grading — independent
	// of official jury enable/disable.
	Uses []UseSpec
	// CompositionOnly is true when this package was loaded only as a uses member
	// of a local package (not a train draft target unless also listed as local).
	CompositionOnly bool
}

// UseSpec is one adversary.yaml uses entry.
type UseSpec struct {
	Name    string
	Version string
	Path    string
}

// DiscoverSiblings finds *-adversary directories next to factoryRoot's parent
// (…/adversarylabs/adversary → …/adversarylabs/*-adversary).
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
		return nil, fmt.Errorf("no sibling *-adversary packages with agent/scope.md (or legacy docs/scope.md) under %s", parent)
	}
	return out, nil
}

// DiscoverRoot loads adversary packages under root.
//
// Single-package workspace: root has adversary.yaml (+ agent/scope.md) → that one package.
// Multi-package workspace: each child with adversary.yaml is a package (e.g. adversaries/*).
//
// Important: do not treat agent/, docs/, src/ as packages just because they contain a
// scope.md fragment — on case-insensitive filesystems SCOPE.md matches scope.md and
// used to mis-discover id=agent, then run.only filtered everything out.
func DiscoverRoot(root string) ([]Package, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	// Prefer the root itself when it is a real package (adversary.yaml present).
	if isAdversaryPackageDir(abs) {
		if pkg, err := loadPackage(abs, filepath.Base(abs)); err == nil {
			return []Package{pkg}, nil
		}
	}
	entries, err := os.ReadDir(abs)
	if err != nil {
		return nil, err
	}
	var out []Package
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		dir := filepath.Join(abs, e.Name())
		if !isAdversaryPackageDir(dir) {
			continue
		}
		pkg, err := loadPackage(dir, e.Name())
		if err != nil {
			continue
		}
		out = append(out, pkg)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	if len(out) == 0 {
		// Last resort: root has scope but no yaml (legacy).
		if pkg, err := loadPackage(abs, filepath.Base(abs)); err == nil {
			return []Package{pkg}, nil
		}
		return nil, fmt.Errorf("no packages with adversary.yaml + agent/scope.md (or legacy docs/scope.md) under %s", abs)
	}
	return out, nil
}

func isAdversaryPackageDir(dir string) bool {
	info, err := os.Stat(filepath.Join(dir, "adversary.yaml"))
	return err == nil && info.Mode().IsRegular()
}

// FilterByIDs keeps packages whose ID or DirName matches one of only (empty = all).
func FilterByIDs(pkgs []Package, only []string) []Package {
	if len(only) == 0 {
		return pkgs
	}
	want := map[string]bool{}
	for _, o := range only {
		o = strings.TrimSpace(strings.ToLower(o))
		if o != "" {
			want[o] = true
		}
	}
	var out []Package
	for _, p := range pkgs {
		id := strings.ToLower(p.ID)
		name := strings.ToLower(p.DirName)
		if want[id] || want[name] || want[strings.ToLower(p.ManifestName)] {
			out = append(out, p)
		}
	}
	return out
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
	// Parse adversary.yaml for name/description/globs/uses.
	raw, err := os.ReadFile(filepath.Join(dir, "adversary.yaml"))
	if err == nil {
		var y struct {
			Name        string `yaml:"name"`
			Description string `yaml:"description"`
			Uses        []struct {
				Name    string `yaml:"name"`
				Version string `yaml:"version"`
				Path    string `yaml:"path"`
			} `yaml:"uses"`
			Triggers struct {
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
			for _, u := range y.Uses {
				pkg.Uses = append(pkg.Uses, UseSpec{
					Name:    strings.TrimSpace(u.Name),
					Version: strings.TrimSpace(u.Version),
					Path:    strings.TrimSpace(u.Path),
				})
			}
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
