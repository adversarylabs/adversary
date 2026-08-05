package cases

import (
	"fmt"
	"strings"
	"time"
)

// ReviewSignal is evidence used to recover the exact reviewed SHA.
type ReviewSignal struct {
	// CommitID from a formal pull request review (review.commit_id).
	ReviewCommitID string
	// OriginalCommitIDs from review comments (comment.original_commit_id).
	OriginalCommitIDs []string
	// TimelineHeadSHAs are head SHAs observed at or near review time.
	TimelineHeadSHAs []string
	// PRHeadSHA is the current refs/pull/N/head (may have moved after force-push).
	PRHeadSHA string
	// SubmittedAt is when the review was submitted.
	SubmittedAt time.Time
}

// ReconstructReviewedSHA picks the exact SHA humans reviewed.
// Preference order (architecture D15):
//  1. formal review commit_id when present and non-empty
//  2. unanimous original_commit_id across review comments
//  3. single distinct original_commit_id
// If none of these yield a trustworthy SHA, returns an Exclusion rather than approximating.
func ReconstructReviewedSHA(sig ReviewSignal) (sha string, source string, excl *Exclusion) {
	if s := strings.TrimSpace(sig.ReviewCommitID); s != "" && looksLikeSHA(s) {
		return s, "review.commit_id", nil
	}

	// Collect unique original commit IDs.
	uniq := map[string]int{}
	for _, id := range sig.OriginalCommitIDs {
		id = strings.TrimSpace(id)
		if id == "" || !looksLikeSHA(id) {
			continue
		}
		uniq[id]++
	}
	switch len(uniq) {
	case 0:
		// Fall through — no comment-level evidence.
	case 1:
		for id := range uniq {
			return id, "comment.original_commit_id", nil
		}
	default:
		// Multiple distinct SHAs: only accept if one dominates all others (unanimous majority of comments).
		var best string
		var bestN int
		total := 0
		for id, n := range uniq {
			total += n
			if n > bestN {
				bestN = n
				best = id
			}
		}
		if bestN == total {
			return best, "comment.original_commit_id", nil
		}
		return "", "", &Exclusion{
			Reason: "ambiguous-reviewed-sha",
			Detail: fmt.Sprintf("multiple original_commit_id values among comments (%d distinct); refuse approximation", len(uniq)),
		}
	}

	// Do not approximate with PR head or timeline — architecture: exclude rather than guess.
	return "", "", &Exclusion{
		Reason: "unrecoverable-reviewed-sha",
		Detail: "no review.commit_id or original_commit_id; exclude rather than use nearby PR head",
	}
}

func looksLikeSHA(s string) bool {
	if len(s) < 7 || len(s) > 40 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// AttachCommentsToRound filters comments that belong to a review round by attachment rules.
func AttachCommentsToRound(comments []Comment, reviewIDs map[int64]bool, reviewedSHA string, windowOpen, windowClose time.Time) []Comment {
	var out []Comment
	for _, c := range comments {
		if c.OriginalCommitID != "" && reviewedSHA != "" && c.OriginalCommitID == reviewedSHA {
			out = append(out, c)
			continue
		}
		if !windowOpen.IsZero() && !c.CreatedAt.IsZero() {
			if c.CreatedAt.Before(windowOpen) {
				continue
			}
			if !windowClose.IsZero() && c.CreatedAt.After(windowClose) {
				continue
			}
			out = append(out, c)
			continue
		}
		// Keep review-body comments with no timing if we have no better filter — caller may pre-filter.
		if c.Kind == "review-body" {
			out = append(out, c)
		}
	}
	return out
}

// CandidateLabelsFromComments extracts expected-concern candidates; only ApprovedAsLabel become gold.
func CandidateLabelsFromComments(comments []Comment) []ExpectedConcern {
	var out []ExpectedConcern
	for i, c := range comments {
		if strings.TrimSpace(c.Body) == "" {
			continue
		}
		// Skip pure style noise heuristics (minimal for first slice).
		if c.Classification == "style or preference" || c.Classification == "project-specific convention" {
			continue
		}
		summary := c.GeneralizedConcern
		if summary == "" {
			summary = truncate(strings.TrimSpace(c.Body), 200)
		}
		out = append(out, ExpectedConcern{
			ID:         fmt.Sprintf("c-%d-%d", c.ID, i),
			Summary:    summary,
			Importance: importanceFromClassification(c.Classification),
			Confidence: "medium",
			Source:     []string{"human-review"},
			File:       c.Path,
			Approved:   c.ApprovedAsLabel,
		})
	}
	return out
}

func importanceFromClassification(class string) string {
	switch class {
	case "accepted and fixed":
		return "high"
	case "accepted but not fixed":
		return "medium"
	default:
		return "medium"
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// ApprovedLabels returns only human-approved expected concerns that are in scope
// for the adversary (or have empty scope for backward compatibility with fixtures
// that predate scope classification).
func ApprovedLabels(labels []ExpectedConcern) []ExpectedConcern {
	var out []ExpectedConcern
	for _, l := range labels {
		if !l.Approved {
			continue
		}
		// Empty scope = legacy fixture gold; treat as in scope.
		if l.Scope == "" || l.Scope == "in_scope" {
			out = append(out, l)
		}
	}
	return out
}

// OutOfScopeLabels returns concerns we deliberately do not grade as misses.
func OutOfScopeLabels(labels []ExpectedConcern) []ExpectedConcern {
	var out []ExpectedConcern
	for _, l := range labels {
		if l.Scope == "out_of_scope" || l.Scope == "unclear" {
			out = append(out, l)
		}
	}
	return out
}
