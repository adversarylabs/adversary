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
}

// UseSpec is one adversary.yaml uses entry.
type UseSpec struct {
	Name    string
	Version string
	Path    string
}

// CanonicalDuplicate records a local checkout omitted because another package
// declares the same adversary.yaml name. ManifestName is the package identity;
// directory-derived IDs only identify a particular local checkout.
type CanonicalDuplicate struct {
	ManifestName string
	Kept         Package
	Ignored      Package
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

// FilterExcludedIDs removes packages whose ID, directory name, or manifest
// name matches an excluded identifier.
func FilterExcludedIDs(pkgs []Package, excluded []string) []Package {
	if len(excluded) == 0 {
		return pkgs
	}
	blocked := map[string]bool{}
	for _, value := range excluded {
		value = strings.TrimSpace(strings.ToLower(value))
		if value != "" {
			blocked[value] = true
		}
	}
	out := make([]Package, 0, len(pkgs))
	for _, p := range pkgs {
		if blocked[strings.ToLower(p.ID)] || blocked[strings.ToLower(p.DirName)] || blocked[strings.ToLower(p.ManifestName)] {
			continue
		}
		out = append(out, p)
	}
	return out
}

// ResolveTrainingPackages applies explicit package selection before canonical
// deduplication, then exclusions. Filtering first is intentional: run.only (or
// --adversary) may name a particular checkout as a temporary local override.
// Without that explicit choice, multiple directories declaring the same
// manifest package must not become separate routing or cycle targets.
//
// onlyMatched is false only when a non-empty only list matched nothing; callers
// retain the existing behavior of keeping all discovered packages in that case.
func ResolveTrainingPackages(pkgs []Package, only, excluded []string) (selected []Package, duplicates []CanonicalDuplicate, onlyMatched bool) {
	selected = pkgs
	onlyMatched = true
	if len(only) > 0 {
		if filtered := FilterByIDs(selected, only); len(filtered) > 0 {
			selected = filtered
		} else {
			onlyMatched = false
		}
	}
	selected, duplicates = DeduplicateCanonical(selected)
	selected = FilterExcludedIDs(selected, excluded)
	return selected, duplicates, onlyMatched
}

// DeduplicateCanonical keeps one local checkout per adversary.yaml name.
// Selection is deterministic and favors a directory-derived ID that matches
// the full or leaf manifest identity (for example go-concurrency for
// go/concurrency, or githubactions for ci/github-actions). Conventional
// *-adversary checkout names, shorter names, and lexical order break ties.
func DeduplicateCanonical(pkgs []Package) ([]Package, []CanonicalDuplicate) {
	groups := map[string][]Package{}
	var keys []string
	for _, pkg := range pkgs {
		key := canonicalPackageKey(pkg)
		if _, ok := groups[key]; !ok {
			keys = append(keys, key)
		}
		groups[key] = append(groups[key], pkg)
	}
	sort.Strings(keys)
	selected := make([]Package, 0, len(keys))
	var duplicates []CanonicalDuplicate
	for _, key := range keys {
		group := groups[key]
		best := group[0]
		for _, candidate := range group[1:] {
			if preferCanonicalPackage(candidate, best) {
				best = candidate
			}
		}
		selected = append(selected, best)
		for _, candidate := range group {
			if candidate.Dir == best.Dir && candidate.ID == best.ID {
				continue
			}
			duplicates = append(duplicates, CanonicalDuplicate{
				ManifestName: best.ManifestName,
				Kept:         best,
				Ignored:      candidate,
			})
		}
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].ID < selected[j].ID })
	sort.Slice(duplicates, func(i, j int) bool {
		if duplicates[i].ManifestName != duplicates[j].ManifestName {
			return duplicates[i].ManifestName < duplicates[j].ManifestName
		}
		return duplicates[i].Ignored.ID < duplicates[j].Ignored.ID
	})
	return selected, duplicates
}

func canonicalPackageKey(pkg Package) string {
	if name := strings.ToLower(strings.Trim(strings.TrimSpace(pkg.ManifestName), "/")); name != "" {
		return "manifest:" + name
	}
	if id := strings.ToLower(strings.TrimSpace(pkg.ID)); id != "" {
		return "id:" + id
	}
	return "dir:" + strings.ToLower(strings.TrimSpace(pkg.DirName))
}

func preferCanonicalPackage(candidate, current Package) bool {
	candidateScore := manifestIdentityScore(candidate)
	currentScore := manifestIdentityScore(current)
	if candidateScore != currentScore {
		return candidateScore > currentScore
	}
	candidateConventional := strings.HasSuffix(strings.ToLower(candidate.DirName), "-adversary")
	currentConventional := strings.HasSuffix(strings.ToLower(current.DirName), "-adversary")
	if candidateConventional != currentConventional {
		return candidateConventional
	}
	if len(candidate.DirName) != len(current.DirName) {
		return len(candidate.DirName) < len(current.DirName)
	}
	if candidate.DirName != current.DirName {
		return candidate.DirName < current.DirName
	}
	return candidate.Dir < current.Dir
}

func manifestIdentityScore(pkg Package) int {
	id := compactIdentity(pkg.ID)
	manifest := strings.Trim(strings.TrimSpace(pkg.ManifestName), "/")
	if id == "" || manifest == "" {
		return 0
	}
	if id == compactIdentity(manifest) {
		return 2
	}
	if slash := strings.LastIndexByte(manifest, '/'); slash >= 0 && id == compactIdentity(manifest[slash+1:]) {
		return 1
	}
	return 0
}

func compactIdentity(value string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return -1
	}, strings.TrimSpace(value))
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
