package cases

import (
	"testing"
	"time"
)

func TestReconstructReviewedSHA_FromReviewCommitID(t *testing.T) {
	sha := "abc123def4567890abc123def4567890abc123de"
	got, source, excl := ReconstructReviewedSHA(ReviewSignal{
		ReviewCommitID: sha,
		PRHeadSHA:      "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
	})
	if excl != nil {
		t.Fatalf("unexpected exclusion: %+v", excl)
	}
	if got != sha {
		t.Fatalf("got %s want %s", got, sha)
	}
	if source != "review.commit_id" {
		t.Fatalf("source %s", source)
	}
}

func TestReconstructReviewedSHA_FromUnanimousComments(t *testing.T) {
	sha := "bbb222ccc333ddd444eee555fff666aaa111bbbb"
	got, source, excl := ReconstructReviewedSHA(ReviewSignal{
		OriginalCommitIDs: []string{sha, sha, sha},
	})
	if excl != nil {
		t.Fatalf("unexpected exclusion: %+v", excl)
	}
	if got != sha || source != "comment.original_commit_id" {
		t.Fatalf("got %s source %s", got, source)
	}
}

func TestReconstructReviewedSHA_AmbiguousCommentsExcluded(t *testing.T) {
	_, _, excl := ReconstructReviewedSHA(ReviewSignal{
		OriginalCommitIDs: []string{
			"aaa111bbbb222ccc333ddd444eee555fff666aaa",
			"bbb222ccc333ddd444eee555fff666aaa111bbbb",
		},
	})
	if excl == nil || excl.Reason != "ambiguous-reviewed-sha" {
		t.Fatalf("expected ambiguous exclusion, got %+v", excl)
	}
}

func TestReconstructReviewedSHA_NoEvidenceExcluded(t *testing.T) {
	// Must NOT approximate with PR head.
	_, _, excl := ReconstructReviewedSHA(ReviewSignal{
		PRHeadSHA: "ccc333ddd444eee555fff666aaa111bbbb222ccc",
	})
	if excl == nil || excl.Reason != "unrecoverable-reviewed-sha" {
		t.Fatalf("expected unrecoverable exclusion, got %+v", excl)
	}
}

func TestCandidateLabelsAndApproved(t *testing.T) {
	comments := []Comment{
		{
			ID: 1, Body: "This goroutine can leak after Shutdown if context is not cancelled properly in the worker.",
			Path: "a.go", Classification: "accepted and fixed", ApprovedAsLabel: true,
			CreatedAt: time.Now(),
		},
		{
			ID: 2, Body: "nit: naming", Classification: "style or preference", ApprovedAsLabel: false,
		},
	}
	labels := CandidateLabelsFromComments(comments)
	if len(labels) != 1 {
		t.Fatalf("expected 1 candidate label, got %d", len(labels))
	}
	approved := ApprovedLabels(labels)
	if len(approved) != 1 || !approved[0].Approved {
		t.Fatalf("approved: %+v", approved)
	}
}

func TestCaseID(t *testing.T) {
	if id := CaseID("opentelemetry-go", 1234, 1); id != "opentelemetry-go-pr-1234-r1" {
		t.Fatalf("id=%s", id)
	}
}
