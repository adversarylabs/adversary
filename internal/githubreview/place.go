package githubreview

import (
	"fmt"
	"strings"

	"github.com/adversarylabs/adversary/internal/githubapi"
)

// HunkSets maps path -> line sets for RIGHT (head) and LEFT (base).
type HunkSets struct {
	Right map[string]map[int]struct{}
	Left  map[string]map[int]struct{}
}

// ParsePRFiles builds line membership from unified patches (includes context lines).
func ParsePRFiles(files []githubapi.PRFile) HunkSets {
	hs := HunkSets{
		Right: map[string]map[int]struct{}{},
		Left:  map[string]map[int]struct{}{},
	}
	for _, f := range files {
		name := strings.TrimSpace(f.Filename)
		if name == "" {
			continue
		}
		if f.Patch == "" {
			// Binary / too large — no inline membership.
			continue
		}
		right, left := parseUnifiedDiff(f.Patch)
		if len(right) > 0 {
			hs.Right[name] = right
		}
		if len(left) > 0 {
			hs.Left[name] = left
		}
		if prev := strings.TrimSpace(f.PreviousFilename); prev != "" && len(left) > 0 {
			// Renames: LEFT may be referenced under old name.
			if hs.Left[prev] == nil {
				hs.Left[prev] = left
			}
		}
	}
	return hs
}

func parseUnifiedDiff(patch string) (right, left map[int]struct{}) {
	right = map[int]struct{}{}
	left = map[int]struct{}{}
	var oldLine, newLine int
	for _, line := range strings.Split(patch, "\n") {
		if strings.HasPrefix(line, "@@") {
			// @@ -l,s +l,s @@
			oldLine, newLine = parseHunkHeader(line)
			continue
		}
		if oldLine == 0 && newLine == 0 {
			continue
		}
		if len(line) == 0 {
			continue
		}
		switch line[0] {
		case ' ':
			// Context: both sides.
			if oldLine > 0 {
				left[oldLine] = struct{}{}
				oldLine++
			}
			if newLine > 0 {
				right[newLine] = struct{}{}
				newLine++
			}
		case '-':
			if oldLine > 0 {
				left[oldLine] = struct{}{}
				oldLine++
			}
		case '+':
			if newLine > 0 {
				right[newLine] = struct{}{}
				newLine++
			}
		case '\\':
			// \ No newline at end of file
		default:
			// ignore
		}
	}
	return right, left
}

func parseHunkHeader(line string) (oldStart, newStart int) {
	// @@ -12,3 +14,5 @@
	line = strings.TrimPrefix(line, "@@")
	parts := strings.Split(line, "@@")
	if len(parts) == 0 {
		return 0, 0
	}
	body := strings.TrimSpace(parts[0])
	fields := strings.Fields(body)
	for _, f := range fields {
		if strings.HasPrefix(f, "-") {
			oldStart = hunkStart(f[1:])
		}
		if strings.HasPrefix(f, "+") {
			newStart = hunkStart(f[1:])
		}
	}
	return oldStart, newStart
}

func hunkStart(s string) int {
	s = strings.Split(s, ",")[0]
	var n int
	_, _ = fmt.Sscanf(s, "%d", &n)
	return n
}

// ApplyPlacement updates plan comments using hunk membership.
// commitOID should be pullRequest.headRefOid.
func ApplyPlacement(plan *CommentPlan, files []githubapi.PRFile, commitOID string) {
	hs := ParsePRFiles(files)
	plan.HeadSHA = commitOID
	plan.Summary.DiffValidated = true
	plan.Summary.Inline = 0
	plan.Summary.ReviewBody = 0
	plan.Summary.Unplaceable = 0
	for i := range plan.Comments {
		c := &plan.Comments[i]
		if c.Placement == "unplaceable" {
			plan.Summary.Unplaceable++
			continue
		}
		if c.Anchor.Path == "" || c.Anchor.Line == nil {
			c.Placement = "review_body"
			if c.PlacementReason == "" {
				c.PlacementReason = "path_only"
			}
			plan.Summary.ReviewBody++
			continue
		}
		path := c.Anchor.Path
		line := *c.Anchor.Line
		end := line
		if c.Anchor.EndLine != nil {
			end = *c.Anchor.EndLine
		}
		// Prefer RIGHT.
		if set := hs.Right[path]; set != nil && rangeInSet(set, line, end) {
			c.Placement = "inline"
			c.PlacementReason = ""
			c.Anchor.Side = "RIGHT"
			if end != line {
				c.Anchor.StartSide = "RIGHT"
			}
			c.Anchor.CommitOID = commitOID
			plan.Summary.Inline++
			continue
		}
		if set := hs.Left[path]; set != nil && rangeInSet(set, line, end) {
			c.Placement = "inline"
			c.PlacementReason = ""
			c.Anchor.Side = "LEFT"
			if end != line {
				c.Anchor.StartSide = "LEFT"
			}
			c.Anchor.CommitOID = commitOID
			plan.Summary.Inline++
			continue
		}
		// Path known but line not on hunk, or file missing from PR.
		c.Placement = "review_body"
		if _, ok := hs.Right[path]; ok || hs.Left[path] != nil {
			c.PlacementReason = "line_not_on_diff"
		} else {
			c.PlacementReason = "path_not_in_pr"
		}
		c.Anchor.Side = ""
		c.Anchor.StartSide = ""
		c.Anchor.CommitOID = ""
		plan.Summary.ReviewBody++
	}
	plan.Summary.Comments = len(plan.Comments)
}

func rangeInSet(set map[int]struct{}, start, end int) bool {
	if end < start {
		start, end = end, start
	}
	for n := start; n <= end; n++ {
		if _, ok := set[n]; !ok {
			return false
		}
	}
	return true
}

// MarkDiffNotFetched sets intent placement without validating hunks.
func MarkDiffNotFetched(plan *CommentPlan) {
	plan.Summary.DiffValidated = false
	plan.Summary.Notes = "diff_not_fetched: placement is intent only"
	plan.Summary.Inline = 0
	plan.Summary.ReviewBody = 0
	plan.Summary.Unplaceable = 0
	for i := range plan.Comments {
		c := &plan.Comments[i]
		if c.Placement == "unplaceable" {
			plan.Summary.Unplaceable++
			continue
		}
		if c.Anchor.Line != nil && c.Anchor.Path != "" {
			c.Placement = "inline"
			c.PlacementReason = "diff_not_fetched"
			plan.Summary.Inline++
		} else {
			c.Placement = "review_body"
			if c.PlacementReason == "" {
				c.PlacementReason = "diff_not_fetched"
			} else if c.PlacementReason != "diff_not_fetched" {
				// keep path_only etc but note unvalidated
			}
			if c.PlacementReason == "path_only" || c.PlacementReason == "no_evidence_path" {
				// keep
			} else {
				c.PlacementReason = "diff_not_fetched"
			}
			plan.Summary.ReviewBody++
		}
	}
}
