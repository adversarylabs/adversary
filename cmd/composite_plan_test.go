package cmd

import (
	"context"
	"fmt"
	"io"
	"testing"

	internaladversary "github.com/adversarylabs/adversary/internal/adversary"
	"github.com/adversarylabs/adversary/pkg/detection"
	"github.com/adversarylabs/adversary/pkg/manifest"
)

type plannerGit struct {
	resolution internaladversary.RunScopeResolution
	regions    []detection.ReviewRegion
}

func (*plannerGit) ChangedFiles(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}

func (g *plannerGit) ResolveRunScope(context.Context, internaladversary.RunScopeRequest) (internaladversary.RunScopeResolution, error) {
	return g.resolution, nil
}

func (g *plannerGit) ChangedRegions(context.Context, string, detection.Context) ([]detection.ReviewRegion, error) {
	return append([]detection.ReviewRegion(nil), g.regions...), nil
}

func TestGroupReviewRegionsHasNoGroupCap(t *testing.T) {
	var regions []detection.ReviewRegion
	for i := 0; i < 9; i++ {
		regions = append(regions, detection.ReviewRegion{Path: string(rune('a'+i)) + ".go", StartLine: 1, EndLine: 1})
	}
	groups := groupReviewRegions(regions, nil)
	if len(groups) != 9 {
		t.Fatalf("groups = %d, want all 9", len(groups))
	}
}

func TestGroupReviewRegionsCombinesNearbyAndGraphRelatedHunks(t *testing.T) {
	regions := []detection.ReviewRegion{
		{Path: "a.go", StartLine: 1, EndLine: 5},
		{Path: "a.go", StartLine: 40, EndLine: 45},
		{Path: "a.go", StartLine: 200, EndLine: 205},
		{Path: "b.go", StartLine: 1, EndLine: 2},
	}
	relations := map[string]map[string]struct{}{"a.go": {"b.go": {}}}
	groups := groupReviewRegions(regions, relations)
	if len(groups) != 1 || len(groups[0]) != 4 {
		t.Fatalf("groups = %#v, want one graph-connected group", groups)
	}
}

func TestGroupReviewRegionsKeepsDistantHunksSeparate(t *testing.T) {
	regions := []detection.ReviewRegion{
		{Path: "a.go", StartLine: 1, EndLine: 5},
		{Path: "a.go", StartLine: 200, EndLine: 205},
	}
	groups := groupReviewRegions(regions, nil)
	if len(groups) != 2 {
		t.Fatalf("groups = %d, want 2", len(groups))
	}
}

func TestProcessRuntimePlansEveryResolvedGroup(t *testing.T) {
	changed := make([]detection.ChangedFile, 0, 6)
	regions := make([]detection.ReviewRegion, 0, 6)
	for i := 0; i < 6; i++ {
		path := string(rune('a'+i)) + ".go"
		changed = append(changed, detection.ChangedFile{Path: path, Status: detection.StatusModified})
		regions = append(regions, detection.ReviewRegion{Path: path, StartLine: 10, EndLine: 15})
	}
	reviewContext := &detection.Context{SchemaVersion: detection.SchemaVersion, RepositoryRoot: t.TempDir(), Mode: detection.ModeBranchComparison, BaseRef: "main", HeadRef: "HEAD", MergeBase: "abc", ChangedFiles: changed}
	git := &plannerGit{resolution: internaladversary.RunScopeResolution{ReviewContext: reviewContext}, regions: regions}
	plan, err := (processRuntime{git: git}).planCompositeReview(context.Background(), &runOptions{path: reviewContext.RepositoryRoot, repoIndex: "off"}, nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if plan.FullContext == nil || len(plan.Groups) != 6 {
		t.Fatalf("plan = %#v, want all 6 groups", plan)
	}
	for i, group := range plan.Groups {
		if group.ID == "" || len(group.Assignment.Regions) != 1 || len(group.Context.ChangedFiles) != 1 {
			t.Fatalf("group[%d] = %#v", i, group)
		}
	}
}

func TestRoutedComposedRunJobsFiltersAndBatchesWithoutDroppingRegions(t *testing.T) {
	full := &detection.Context{SchemaVersion: detection.SchemaVersion, ChangedFiles: []detection.ChangedFile{
		{Path: "a.go", Status: detection.StatusModified},
		{Path: "b.ts", Status: detection.StatusModified},
		{Path: "c.go", Status: detection.StatusModified},
	}}
	group := func(id, path string, start, end int) compositeReviewGroup {
		region := detection.ReviewRegion{Path: path, StartLine: start, EndLine: end}
		return compositeReviewGroup{
			ID:         id,
			Context:    internaladversary.ReviewContextForFiles(*full, []string{path}),
			Assignment: detection.ReviewAssignment{ID: id, Regions: []detection.ReviewRegion{region}},
		}
	}
	plan := compositeReviewPlan{
		FullContext: full,
		Groups: []compositeReviewGroup{
			group("group-001", "a.go", 1, 200),
			group("group-002", "b.ts", 1, 100),
			group("group-003", "c.go", 1, 250),
		},
		Manifests: map[string]manifest.Manifest{
			"review/code":     {Detection: manifest.Detection{Files: []string{"**/*"}}},
			"lang/go":         {Detection: manifest.Detection{Files: []string{"*.go", "**/*.go"}}},
			"lang/typescript": {Detection: manifest.Detection{Files: []string{"*.ts", "**/*.ts"}}},
		},
	}
	refs := []string{"review/code", "lang/go", "lang/typescript"}
	jobs, stats := routedComposedRunJobs("review/code", refs, plan, 300, 0, true)
	if len(jobs) != 6 { // root full + code(2) + go(2) + TypeScript(1)
		t.Fatalf("jobs = %d, want 6: %#v", len(jobs), jobs)
	}
	if stats.SkippedAssignments != 3 || stats.RoutedAssignments != 6 {
		t.Fatalf("stats = %#v", stats)
	}
	covered := map[string]int{}
	for _, job := range jobs[1:] {
		covered[job.ref] += job.regions
		if job.scope == "" || job.lines < 1 || job.groups < 1 {
			t.Fatalf("invalid routed job: %#v", job)
		}
	}
	if covered["review/code"] != 3 || covered["lang/go"] != 2 || covered["lang/typescript"] != 1 {
		t.Fatalf("covered regions = %#v", covered)
	}
}

func TestRoutedComposedRunJobsCanKeepRootToFullChange(t *testing.T) {
	full := &detection.Context{SchemaVersion: detection.SchemaVersion, ChangedFiles: []detection.ChangedFile{{Path: "a.go", Status: detection.StatusModified}}}
	region := detection.ReviewRegion{Path: "a.go", StartLine: 1, EndLine: 20}
	plan := compositeReviewPlan{
		FullContext: full,
		Groups: []compositeReviewGroup{{
			ID: "group-001", Context: *full,
			Assignment: detection.ReviewAssignment{ID: "group-001", Regions: []detection.ReviewRegion{region}},
		}},
		Manifests: map[string]manifest.Manifest{
			"review/code": {Detection: manifest.Detection{Files: []string{"**/*"}}},
			"lang/go":     {Detection: manifest.Detection{Files: []string{"**/*.go"}}},
		},
	}

	jobs, stats := routedComposedRunJobs("review/code", []string{"review/code", "lang/go"}, plan, 300, 0, false)
	if len(jobs) != 2 {
		t.Fatalf("jobs = %d, want root full-change plus one specialist: %#v", len(jobs), jobs)
	}
	if jobs[0].ref != "review/code" || jobs[0].scope != "full-change" || jobs[1].ref != "lang/go" {
		t.Fatalf("unexpected jobs: %#v", jobs)
	}
	if stats.CandidateAssignments != 1 || stats.RoutedAssignments != 1 {
		t.Fatalf("stats = %#v", stats)
	}
}

func TestBatchCompositeReviewGroupsCapsIndependentGroups(t *testing.T) {
	groups := make([]compositeReviewGroup, 7)
	for index := range groups {
		region := detection.ReviewRegion{Path: fmt.Sprintf("file-%d.go", index), StartLine: 1, EndLine: 10}
		groups[index] = compositeReviewGroup{
			ID:         fmt.Sprintf("group-%03d", index+1),
			Assignment: detection.ReviewAssignment{ID: fmt.Sprintf("group-%03d", index+1), Regions: []detection.ReviewRegion{region}},
		}
	}
	batches := batchCompositeReviewGroups(groups, 600, 3)
	if len(batches) != 3 || batchGroupCount(batches[0]) != 3 || batchGroupCount(batches[1]) != 3 || batchGroupCount(batches[2]) != 1 {
		t.Fatalf("unexpected batches: %#v", batches)
	}
}

func TestExhaustiveComposedRunJobsRoutesEveryReviewerToEveryGroup(t *testing.T) {
	full := &detection.Context{SchemaVersion: detection.SchemaVersion}
	plan := compositeReviewPlan{FullContext: full}
	for i := 0; i < 7; i++ {
		id := string(rune('a' + i))
		plan.Groups = append(plan.Groups, compositeReviewGroup{ID: id, Assignment: detection.ReviewAssignment{ID: id}})
	}
	refs := []string{"review/code", "go/concurrency", "review/conventions"}
	jobs := exhaustiveComposedRunJobs("review/code", refs, plan)
	if len(jobs) != 1+len(plan.Groups)*len(refs) {
		t.Fatalf("jobs = %d, want %d", len(jobs), 1+len(plan.Groups)*len(refs))
	}
	counts := map[string]int{}
	for _, job := range jobs[1:] {
		counts[job.ref]++
	}
	for _, ref := range refs {
		if counts[ref] != len(plan.Groups) {
			t.Fatalf("%s jobs = %d, want %d", ref, counts[ref], len(plan.Groups))
		}
	}
}
