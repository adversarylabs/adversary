package adversary

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"

	"github.com/adversarylabs/adversary/pkg/detection"
)

// ChangeRegionResolver resolves every changed hunk in an immutable review
// context. It deliberately has no group or region limit.
type ChangeRegionResolver interface {
	ChangedRegions(context.Context, string, detection.Context) ([]detection.ReviewRegion, error)
}

var gitHunkHeader = regexp.MustCompile(`(?m)^@@ -[0-9]+(?:,[0-9]+)? \+([0-9]+)(?:,([0-9]+))? @@`)

func (g CommandGitDiffer) ChangedRegions(ctx context.Context, repoPath string, review detection.Context) ([]detection.ReviewRegion, error) {
	if err := g.validate(); err != nil {
		return nil, err
	}
	if repoPath == "" {
		repoPath = review.RepositoryRoot
	}
	if err := g.verifyRepository(ctx, repoPath); err != nil {
		return nil, err
	}

	var base, head string
	if review.Mode == detection.ModeDirtyWorktree {
		base = "HEAD"
	} else {
		base = review.MergeBase
		if base == "" {
			base = review.BaseRef
		}
		head = review.HeadRef
		if head == "" {
			head = "HEAD"
		}
	}
	if !validRevisionArgument(base) || (head != "" && !validRevisionArgument(head)) {
		return nil, fmt.Errorf("review context contains an invalid revision")
	}

	regions := make([]detection.ReviewRegion, 0, len(review.ChangedFiles))
	for _, changed := range review.ChangedFiles {
		args := []string{"diff", "--no-ext-diff", "--no-color", "--unified=0", base}
		if head != "" {
			args = append(args, head)
		}
		args = append(args, "--", changed.Path)
		stdout, stderr, err := g.run(ctx, repoPath, args...)
		if err != nil {
			return nil, fmt.Errorf("git diff changed regions for %q: %s", changed.Path, bytes.TrimSpace(stderr))
		}
		fileRegions, err := parseChangedRegions(changed.Path, stdout)
		if err != nil {
			return nil, err
		}
		if len(fileRegions) == 0 {
			// Untracked files and rare binary/type-only changes do not have a text
			// hunk. Keep them in coverage with a stable file-level assignment.
			end := 1
			if changed.Additions != nil && *changed.Additions > end {
				end = *changed.Additions
			}
			fileRegions = append(fileRegions, detection.ReviewRegion{Path: changed.Path, StartLine: 1, EndLine: end})
		}
		regions = append(regions, fileRegions...)
	}
	sort.Slice(regions, func(i, j int) bool {
		if regions[i].Path != regions[j].Path {
			return regions[i].Path < regions[j].Path
		}
		if regions[i].StartLine != regions[j].StartLine {
			return regions[i].StartLine < regions[j].StartLine
		}
		return regions[i].EndLine < regions[j].EndLine
	})
	return regions, nil
}

func parseChangedRegions(path string, patch []byte) ([]detection.ReviewRegion, error) {
	matches := gitHunkHeader.FindAllSubmatch(patch, -1)
	regions := make([]detection.ReviewRegion, 0, len(matches))
	for _, match := range matches {
		start, err := strconv.Atoi(string(match[1]))
		if err != nil || start < 0 {
			return nil, fmt.Errorf("parse git hunk start for %q", path)
		}
		count := 1
		if len(match[2]) > 0 {
			count, err = strconv.Atoi(string(match[2]))
			if err != nil || count < 0 {
				return nil, fmt.Errorf("parse git hunk count for %q", path)
			}
		}
		// Deletion-only hunks use a zero-length new range. Anchor the assignment
		// to the surviving line at the deletion site so the change is not lost.
		if start < 1 {
			start = 1
		}
		end := start
		if count > 1 {
			end = start + count - 1
		}
		regions = append(regions, detection.ReviewRegion{Path: path, StartLine: start, EndLine: end})
	}
	return regions, nil
}
