// Package compose expands adversary.yaml "uses" composition into a flat run list.
//
// Composition roots (person/torvalds, lang/go, …) declare other adversaries to
// run. The CLI expands transitively, dedupes, and runs each package. GitHub
// comment voice is owned by the CLI entry package, not by members.
package compose

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/adversarylabs/adversary/pkg/manifest"
)

// DefaultMaxDepth caps nested uses expansion (meta packs like go → go/*).
const DefaultMaxDepth = 8

// Loader loads a package manifest for a run reference (local path or installed name).
type Loader interface {
	// Load returns the manifest and the absolute package directory that contains
	// adversary.yaml (for resolving relative uses[].path).
	Load(ref string) (m manifest.Manifest, packageDir string, err error)
}

// Options controls Expand.
type Options struct {
	// MaxDepth limits transitive expansion (0 = DefaultMaxDepth).
	MaxDepth int
	// IncludeRoots keeps CLI entry packages in the run list (default true).
	// Members are always included when discovered.
	IncludeRoots bool
}

// Result is the expanded run set plus voice roots for the entry packages.
type Result struct {
	// Refs is the ordered list of adversary refs to run (roots first, then
	// members in declaration order, BFS by depth).
	Refs []string
	// VoiceRoots are absolute package directories for CLI entry roots that were
	// successfully loaded (prefer these for agent/voice.md resolution).
	VoiceRoots []string
	// Expanded is true when any uses entry was added beyond the original roots.
	Expanded bool
}

// Expand flattens roots and their uses graphs into a deduped run list.
// Cycles are skipped (already-seen ref). Missing load is returned as an error.
func Expand(roots []string, load Loader, opts Options) (Result, error) {
	if load == nil {
		return Result{}, fmt.Errorf("compose: loader is required")
	}
	maxDepth := opts.MaxDepth
	if maxDepth <= 0 {
		maxDepth = DefaultMaxDepth
	}
	includeRoots := true
	// IncludeRoots defaults true; only skip when explicitly false via zero-value
	// would be wrong — use pointer or always include. Always include roots.
	_ = includeRoots

	var out Result
	seen := map[string]struct{}{}
	seenPackages := map[string]struct{}{}
	type item struct {
		ref    string
		depth  int
		isRoot bool
	}
	var queue []item
	for _, r := range roots {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		queue = append(queue, item{ref: r, depth: 0, isRoot: true})
	}
	if len(queue) == 0 {
		return Result{}, fmt.Errorf("compose: no adversary references")
	}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		key := normalizeRefKey(cur.ref)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		m, packageDir, err := load.Load(cur.ref)
		runRef := cur.ref
		if err == nil {
			identity := strings.ToLower(strings.TrimSpace(m.Name)) + "@" + strings.TrimSpace(m.Version)
			if identity != "@" {
				if _, ok := seenPackages[identity]; ok {
					continue
				}
				seenPackages[identity] = struct{}{}
			}
		}
		if err == nil && packageDir != "" {
			if canon, canonErr := canonicalPath(packageDir); canonErr == nil {
				// Alias every path form of this package dir so ./pkg, /abs/pkg,
				// and symlink paths that resolve to the same tree share one key.
				seen[canon] = struct{}{}
				if isFilesystemRef(cur.ref) {
					runRef = canon
					seen[normalizeRefKey(cur.ref)] = struct{}{}
				}
			}
		}

		// Always run roots; always run discovered members.
		out.Refs = append(out.Refs, runRef)

		if err != nil {
			// Leave as a leaf: run will pull/resolve and surface errors.
			// Avoid failing the whole multi-run expand on a missing optional member
			// graph; composition is best-effort load for expansion only.
			continue
		}
		if cur.isRoot && packageDir != "" {
			if canon, err := canonicalPath(packageDir); err == nil {
				out.VoiceRoots = appendUnique(out.VoiceRoots, canon)
			} else {
				out.VoiceRoots = appendUnique(out.VoiceRoots, packageDir)
			}
		}
		if cur.depth >= maxDepth {
			continue
		}
		for i, u := range m.Uses {
			member, err := manifest.UseReference(packageDir, u)
			if err != nil {
				return Result{}, fmt.Errorf("compose: %q uses[%d]: %w", cur.ref, i, err)
			}
			// Prefer canonical paths for local members so dedupe matches roots.
			if isFilesystemRef(member) {
				if canon, err := canonicalPath(member); err == nil {
					member = canon
				}
			}
			mk := normalizeRefKey(member)
			if _, ok := seen[mk]; ok {
				continue
			}
			// Defer seen until dequeue so order stays BFS and we still enqueue once.
			queue = append(queue, item{ref: member, depth: cur.depth + 1, isRoot: false})
			out.Expanded = true
		}
	}
	return out, nil
}

// normalizeRefKey produces a stable dedupe key. Filesystem refs are absolutized
// and symlink-resolved so relative roots, uses[].path, and symlink aliases that
// point at the same tree collapse to one run.
func normalizeRefKey(ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return ""
	}
	if isFilesystemRef(ref) {
		if canon, err := canonicalPath(ref); err == nil {
			return canon
		}
		return filepath.Clean(ref)
	}
	return strings.ToLower(ref)
}

// canonicalPath returns an absolute, symlink-resolved path when possible.
// EvalSymlinks may fail for a not-yet-created path; then Abs+Clean is used.
func canonicalPath(p string) (string, error) {
	abs, err := filepath.Abs(filepath.Clean(p))
	if err != nil {
		return "", err
	}
	if eval, err := filepath.EvalSymlinks(abs); err == nil {
		return eval, nil
	}
	return abs, nil
}

// isFilesystemRef reports whether ref is a local path (not a registry name/tag).
// Registry names like go/concurrency stay as names; ./pkg, ../pkg, ., and
// absolute paths are filesystem refs.
func isFilesystemRef(ref string) bool {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return false
	}
	if filepath.IsAbs(ref) || ref == "." || ref == ".." {
		return true
	}
	return strings.HasPrefix(ref, "./") || strings.HasPrefix(ref, "../")
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}
