package application

import (
	"context"
	"fmt"
	"path/filepath"

	internaladversary "github.com/adversarylabs/adversary/internal/adversary"
	"github.com/adversarylabs/adversary/pkg/compose"
	"github.com/adversarylabs/adversary/pkg/detection"
	"github.com/adversarylabs/adversary/pkg/manifest"
)

type ComposeMetadata struct {
	Manifest  manifest.Manifest
	Reference string
	Directory string
	Error     error
}
type ComposeMetadataFunc func(context.Context, []string) (map[string]ComposeMetadata, error)

type ComposeSelection struct {
	MetadataAvailable bool   `json:"-"`
	Reference         string `json:"reference"`
	ResolvedReference string `json:"resolved_reference"`
	Selected          bool   `json:"selected"`
	Reason            string `json:"reason"`
	Root              bool   `json:"root"`
}
type ComposePlan struct {
	Complete   bool               `json:"complete"`
	Refs       []string           `json:"adversaries"`
	Selections []ComposeSelection `json:"selections"`
	VoiceRoots []string           `json:"-"`
}

// PlanCompose discovers the entire metadata graph before downloading runnable
// packages. A filtered intermediate composite does not hide relevant children.
func PlanCompose(ctx context.Context, roots []string, load ComposeMetadataFunc, scope *detection.Context) (ComposePlan, error) {
	plan := ComposePlan{Complete: true, Refs: []string{}, Selections: []ComposeSelection{}}
	if load == nil {
		return plan, fmt.Errorf("compose: metadata loader is required")
	}
	type node struct {
		ref   string
		depth int
	}
	queue := []node{}
	rootSet := map[string]bool{}
	for _, ref := range roots {
		queue = append(queue, node{ref, 0})
		rootSet[ref] = true
	}
	seen := map[string]bool{}
	identities := map[string]int{}
	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			return plan, err
		}
		wave := queue
		queue = nil
		refs := []string{}
		pending := []node{}
		for _, n := range wave {
			if !seen[n.ref] {
				seen[n.ref] = true
				refs = append(refs, n.ref)
				pending = append(pending, n)
			}
		}
		metadata, err := load(ctx, refs)
		if err != nil {
			return plan, fmt.Errorf("load composition metadata: %w", err)
		}
		for _, n := range pending {
			m, exists := metadata[n.ref]
			if !exists {
				m.Error = fmt.Errorf("metadata unavailable")
			}
			if m.Error != nil {
				plan.Complete = false
			}
			resolved := m.Reference
			if resolved == "" {
				resolved = n.ref
			}
			selection := ComposeSelection{Reference: n.ref, ResolvedReference: resolved, Root: rootSet[n.ref], Selected: true, MetadataAvailable: m.Error == nil}
			switch {
			case selection.Root:
				selection.Reason = "explicit composition root"
				if m.Error != nil {
					selection.Reason += "; metadata unavailable, dependency graph incomplete"
				}
			case m.Error != nil:
				selection.Reason = "metadata unavailable; retained"
			case scope == nil:
				selection.Reason = "repository context unavailable; retained"
			default:
				selection.Selected, selection.Reason = internaladversary.SelectBeforeDownload(m.Manifest, *scope)
			}
			// A name/version identity deduplicates local aliases and registry aliases.
			identity := resolved
			if m.Error == nil {
				identity = m.Manifest.Name + "@" + m.Manifest.Version
			}
			// Retain every explicit root's voice directory, even when aliases
			// collapse to one executable package. The first explicit root wins.
			if selection.Root && m.Directory != "" {
				plan.VoiceRoots = append(plan.VoiceRoots, m.Directory)
			}
			if previous, ok := identities[identity]; ok {
				if selection.Root && !plan.Selections[previous].Root {
					plan.Selections[previous] = selection
				}
				continue
			}
			identities[identity] = len(plan.Selections)
			plan.Selections = append(plan.Selections, selection)
			if m.Error != nil {
				continue
			}
			if n.depth >= compose.DefaultMaxDepth && len(m.Manifest.Uses) > 0 {
				return plan, fmt.Errorf("composition exceeds maximum depth %d", compose.DefaultMaxDepth)
			}
			for _, use := range m.Manifest.Uses {
				if use.Path != "" && m.Directory == "" {
					return plan, fmt.Errorf("remote composition %s has a relative path dependency", n.ref)
				}
				ref, err := manifest.UseReference(m.Directory, use)
				if err != nil {
					return plan, err
				}
				queue = append(queue, node{ref, n.depth + 1})
			}
		}
	}
	for _, selection := range plan.Selections {
		if selection.Selected {
			plan.Refs = append(plan.Refs, selection.ResolvedReference)
		}
	}
	return plan, nil
}

// LocalComposeMetadata never pulls. Installed packages are read through the
// resolver so offline composition keeps working.
func LocalComposeMetadata(ctx context.Context, resolver Resolver, ref string) ComposeMetadata {
	loader := composeLoader{ctx: ctx, resolver: resolver}
	m, dir, err := loader.Load(ref)
	return ComposeMetadata{Manifest: m, Reference: ref, Directory: dir, Error: err}
}

func ComposePackageRoot(ctx context.Context, resolver Resolver, ref string) string {
	result := LocalComposeMetadata(ctx, resolver, ref)
	if result.Error != nil {
		return ""
	}
	dir, _ := filepath.Abs(result.Directory)
	return dir
}
