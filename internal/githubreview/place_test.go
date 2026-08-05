package githubreview

import (
	"testing"

	"github.com/adversarylabs/adversary/internal/githubapi"
)

func TestParseUnifiedDiffIncludesContext(t *testing.T) {
	// @@ -10,3 +10,4 @@ means old starts 10, new starts 10
	// space line10, - line11, + line11new, space line12
	patch := "@@ -10,3 +10,4 @@\n line10\n-line11old\n+line11new\n line12\n"
	right, left := parseUnifiedDiff(patch)
	// RIGHT: 10 (ctx), 11 (add), 12 (ctx)
	for _, n := range []int{10, 11, 12} {
		if _, ok := right[n]; !ok {
			t.Fatalf("right missing %d: %#v", n, right)
		}
	}
	// LEFT: 10 (ctx), 11 (del), 12 (ctx)
	for _, n := range []int{10, 11, 12} {
		if _, ok := left[n]; !ok {
			t.Fatalf("left missing %d: %#v", n, left)
		}
	}
}

func TestApplyPlacementInlineVsBody(t *testing.T) {
	line11 := 11
	line99 := 99
	plan := CommentPlan{
		Comments: []PlannedComment{
			{FindingID: "1", Placement: "inline", Anchor: Anchor{Path: "a.go", Line: &line11}},
			{FindingID: "2", Placement: "inline", Anchor: Anchor{Path: "a.go", Line: &line99}},
			{FindingID: "3", Placement: "review_body", Anchor: Anchor{Path: "a.go"}},
		},
	}
	patch := "@@ -10,3 +10,4 @@\n line10\n-line11old\n+line11new\n line12\n"
	files := []githubapi.PRFile{{Filename: "a.go", Patch: patch}}
	ApplyPlacement(&plan, files, "abc123")
	if plan.Comments[0].Placement != "inline" || plan.Comments[0].Anchor.Side != "RIGHT" {
		t.Fatalf("%#v", plan.Comments[0])
	}
	if plan.Comments[0].Anchor.CommitOID != "abc123" {
		t.Fatal(plan.Comments[0].Anchor.CommitOID)
	}
	if plan.Comments[1].Placement != "review_body" || plan.Comments[1].PlacementReason != "line_not_on_diff" {
		t.Fatalf("%#v", plan.Comments[1])
	}
	if plan.Comments[2].Placement != "review_body" {
		t.Fatalf("%#v", plan.Comments[2])
	}
	for _, c := range plan.Comments {
		if c.Placement == "unresolved" {
			t.Fatal("unresolved enum forbidden")
		}
	}
}

func TestMarkDiffNotFetched(t *testing.T) {
	line := 3
	plan := CommentPlan{Comments: []PlannedComment{
		{Placement: "inline", Anchor: Anchor{Path: "x.go", Line: &line}},
	}}
	MarkDiffNotFetched(&plan)
	if plan.Comments[0].Placement != "inline" || plan.Comments[0].PlacementReason != "diff_not_fetched" {
		t.Fatalf("%#v", plan.Comments[0])
	}
	if plan.Summary.DiffValidated {
		t.Fatal("expected not validated")
	}
}
