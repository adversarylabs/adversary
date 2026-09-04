package cmd

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	internaladversary "github.com/adversarylabs/adversary/internal/adversary"
	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/pkg/adversarylabs"
	"github.com/adversarylabs/adversary/pkg/detection"
	"github.com/adversarylabs/adversary/pkg/manifest"
	"github.com/adversarylabs/adversary/pkg/repoindex"
)

type compositeReviewGroup struct {
	ID         string
	Context    detection.Context
	Assignment detection.ReviewAssignment
}

type compositeReviewPlan struct {
	FullContext *detection.Context
	Groups      []compositeReviewGroup
	Manifests   map[string]manifest.Manifest
	Phases      []adversarylabs.RunUsagePhase
}

type compositeReviewPlanner interface {
	planCompositeReview(context.Context, *runOptions, []string, io.Writer) (compositeReviewPlan, error)
}

func (p processRuntime) planCompositeReview(ctx context.Context, opts *runOptions, refs []string, stderr io.Writer) (compositeReviewPlan, error) {
	plan := compositeReviewPlan{Manifests: make(map[string]manifest.Manifest, len(refs))}
	phaseStarted := time.Now()
	resolvedOpts, _, err := p.resolveRunScope(ctx, application.AdversaryRunOptions{
		RepoPath: opts.path, BaseRef: opts.base, HeadRef: opts.head, AllFiles: opts.allFiles, ReviewContext: opts.reviewContext,
	})
	if err != nil {
		return compositeReviewPlan{}, err
	}
	plan.Phases = append(plan.Phases, runUsagePhase("resolve-scope", phaseStarted, time.Now()))
	if resolvedOpts.AllFiles || resolvedOpts.ReviewContext == nil || len(resolvedOpts.ReviewContext.ChangedFiles) == 0 {
		return plan, nil
	}
	full := *resolvedOpts.ReviewContext
	plan.FullContext = &full
	phaseStarted = time.Now()
	regions := fallbackReviewRegions(full)
	if resolver, ok := p.git.(internaladversary.ChangeRegionResolver); ok {
		resolved, resolveErr := resolver.ChangedRegions(ctx, opts.path, full)
		if resolveErr != nil {
			fmt.Fprintf(stderr, "Warning: changed-hunk resolution failed; reviewing one group per changed file: %v\n", resolveErr)
		} else if len(resolved) > 0 {
			regions = resolved
		}
	}
	plan.Phases = append(plan.Phases, runUsagePhase("resolve-regions", phaseStarted, time.Now()))

	phaseStarted = time.Now()
	groups := groupReviewRegions(regions, nil)
	mode, modeErr := repoindex.ParseMode(opts.repoIndex)
	if modeErr == nil && (mode == repoindex.ModeGraph || mode == repoindex.ModeGraphForce) {
		repoRoot := full.RepositoryRoot
		if repoRoot == "" {
			repoRoot = opts.path
		}
		if repoRoot == "" {
			repoRoot = "."
		}
		handle, graphErr := repoindex.EnsureV2(repoRoot, mode, stderr)
		if graphErr != nil {
			fmt.Fprintf(stderr, "Warning: repository graph could not refine review groups: %v\n", graphErr)
		} else if handle != nil {
			graph, openErr := repoindex.OpenV2(handle.Dir)
			if openErr != nil {
				fmt.Fprintf(stderr, "Warning: repository graph could not be opened for review grouping: %v\n", openErr)
			} else {
				relations := changedFileRelations(graph, full.ChangedFiles)
				_ = graph.Close()
				groups = groupReviewRegions(regions, relations)
			}
		}
	}
	plan.Phases = append(plan.Phases, runUsagePhase("build-review-graph", phaseStarted, time.Now()))

	for i, grouped := range groups {
		id := fmt.Sprintf("group-%03d", i+1)
		paths := uniqueRegionPaths(grouped)
		plan.Groups = append(plan.Groups, compositeReviewGroup{
			ID:         id,
			Context:    internaladversary.ReviewContextForFiles(full, paths),
			Assignment: detection.ReviewAssignment{ID: id, Regions: grouped},
		})
	}
	phaseStarted = time.Now()
	files := p.files
	if files == nil {
		files = internaladversary.OSRuntimeFiles{}
	}
	for _, ref := range refs {
		resolved, resolveErr := internaladversary.ResolveReferenceWithRuntime(canonicalCatalogReference(ref), p.resolver, files)
		if resolveErr != nil || resolved.Manifest == nil {
			if resolveErr != nil {
				fmt.Fprintf(stderr, "Warning: %s manifest could not be loaded for composition routing; retaining exhaustive coverage: %v\n", ref, resolveErr)
			}
			continue
		}
		plan.Manifests[ref] = *resolved.Manifest
	}
	plan.Phases = append(plan.Phases, runUsagePhase("resolve-reviewers", phaseStarted, time.Now()))
	return plan, nil
}

func runUsagePhase(name string, started, ended time.Time) adversarylabs.RunUsagePhase {
	return adversarylabs.RunUsagePhase{
		Name: name, Status: "completed",
		StartedAtUnixNano: strconv.FormatInt(started.UnixNano(), 10),
		EndedAtUnixNano:   strconv.FormatInt(ended.UnixNano(), 10),
	}
}

func fallbackReviewRegions(review detection.Context) []detection.ReviewRegion {
	regions := make([]detection.ReviewRegion, 0, len(review.ChangedFiles))
	for _, changed := range review.ChangedFiles {
		end := 1
		if changed.Additions != nil && *changed.Additions > end {
			end = *changed.Additions
		}
		regions = append(regions, detection.ReviewRegion{Path: changed.Path, StartLine: 1, EndLine: end})
	}
	return regions
}

// groupReviewRegions forms deterministic connected components. Nearby hunks in
// one file and changed files connected by imports/tests share a group. There is
// intentionally no maximum group count: every region is always assigned.
func groupReviewRegions(input []detection.ReviewRegion, relations map[string]map[string]struct{}) [][]detection.ReviewRegion {
	regions := append([]detection.ReviewRegion(nil), input...)
	sort.Slice(regions, func(i, j int) bool {
		if regions[i].Path != regions[j].Path {
			return regions[i].Path < regions[j].Path
		}
		if regions[i].StartLine != regions[j].StartLine {
			return regions[i].StartLine < regions[j].StartLine
		}
		return regions[i].EndLine < regions[j].EndLine
	})
	parent := make([]int, len(regions))
	for i := range parent {
		parent[i] = i
	}
	var find func(int) int
	find = func(value int) int {
		if parent[value] != value {
			parent[value] = find(parent[value])
		}
		return parent[value]
	}
	union := func(a, b int) {
		a, b = find(a), find(b)
		if a != b {
			parent[b] = a
		}
	}
	for i := range regions {
		for j := i + 1; j < len(regions); j++ {
			if regions[i].Path == regions[j].Path {
				if regions[j].StartLine-regions[i].EndLine <= 80 {
					union(i, j)
				}
				continue
			}
			if _, ok := relations[regions[i].Path][regions[j].Path]; ok {
				union(i, j)
			}
		}
	}
	byRoot := map[int][]detection.ReviewRegion{}
	var order []int
	for i, region := range regions {
		root := find(i)
		if _, ok := byRoot[root]; !ok {
			order = append(order, root)
		}
		byRoot[root] = append(byRoot[root], region)
	}
	groups := make([][]detection.ReviewRegion, 0, len(order))
	for _, root := range order {
		groups = append(groups, byRoot[root])
	}
	return groups
}

func changedFileRelations(graph *repoindex.V2Graph, files []detection.ChangedFile) map[string]map[string]struct{} {
	changed := make(map[string]struct{}, len(files))
	for _, file := range files {
		changed[filepath.ToSlash(file.Path)] = struct{}{}
	}
	relations := make(map[string]map[string]struct{}, len(changed))
	connect := func(a, b string) {
		a, b = filepath.ToSlash(a), filepath.ToSlash(b)
		if a == "" || b == "" || a == b {
			return
		}
		if _, ok := changed[a]; !ok {
			return
		}
		if _, ok := changed[b]; !ok {
			return
		}
		if relations[a] == nil {
			relations[a] = map[string]struct{}{}
		}
		if relations[b] == nil {
			relations[b] = map[string]struct{}{}
		}
		relations[a][b] = struct{}{}
		relations[b][a] = struct{}{}
	}
	for path := range changed {
		if page, err := graph.ImportsOf(path, "", 1000); err == nil {
			for _, edge := range page.Items {
				connect(path, edge.ToPath)
			}
		}
		if page, err := graph.ImportersOf(path, "", 1000); err == nil {
			for _, edge := range page.Items {
				connect(path, edge.FromPath)
			}
		}
		if page, err := graph.RelatedTests(path, 0, "", 1000); err == nil {
			for _, link := range page.Items {
				connect(path, link.TestPath)
			}
		}
	}
	return relations
}

func uniqueRegionPaths(regions []detection.ReviewRegion) []string {
	seen := map[string]struct{}{}
	var paths []string
	for _, region := range regions {
		path := strings.TrimSpace(filepath.ToSlash(region.Path))
		if _, ok := seen[path]; ok || path == "" {
			continue
		}
		seen[path] = struct{}{}
		paths = append(paths, path)
	}
	return paths
}
