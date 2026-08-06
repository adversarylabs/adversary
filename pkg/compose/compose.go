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
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		// Always run roots; always run discovered members.
		out.Refs = append(out.Refs, cur.ref)

		m, packageDir, err := load.Load(cur.ref)
		if err != nil {
			// Leave as a leaf: run will pull/resolve and surface errors.
			// Avoid failing the whole multi-run expand on a missing optional member
			// graph; composition is best-effort load for expansion only.
			continue
		}
		if cur.isRoot && packageDir != "" {
			abs := packageDir
			if a, err := filepath.Abs(packageDir); err == nil {
				abs = a
			}
			out.VoiceRoots = appendUnique(out.VoiceRoots, abs)
		}
		if cur.depth >= maxDepth {
			continue
		}
		for i, u := range m.Uses {
			member, err := manifest.UseReference(packageDir, u)
			if err != nil {
				return Result{}, fmt.Errorf("compose: %q uses[%d]: %w", cur.ref, i, err)
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

func normalizeRefKey(ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return ""
	}
	// Absolute paths: clean for dedupe.
	if filepath.IsAbs(ref) || looksLikePath(ref) {
		return filepath.Clean(ref)
	}
	return strings.ToLower(ref)
}

func looksLikePath(ref string) bool {
	if strings.HasPrefix(ref, "./") || strings.HasPrefix(ref, "../") {
		return true
	}
	if strings.Contains(ref, string(filepath.Separator)) && !strings.Contains(ref, ":") {
		// Heuristic: local relative path with separators and no tag colon.
		// name/with/slashes is also a registry name — prefer name form when it
		// matches nameRE-like. If it starts with . or is abs we already handled.
		return strings.HasPrefix(ref, ".")
	}
	return false
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}
