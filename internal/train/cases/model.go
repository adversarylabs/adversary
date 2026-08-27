package cases

import (
	"time"
)

// Case is a single review round of a pull request (not the PR itself).
type Case struct {
	SchemaVersion int    `json:"schema_version" yaml:"schema_version"`
	ID            string `json:"id" yaml:"id"`

	Repository  Repository  `json:"repository" yaml:"repository"`
	PullRequest PullRequest `json:"pull_request" yaml:"pull_request"`

	ReviewEvent    ReviewEvent    `json:"review_event" yaml:"review_event"`
	EvidenceWindow EvidenceWindow `json:"evidence_window" yaml:"evidence_window"`

	Comments []Comment `json:"comments" yaml:"comments"`
	FollowUp FollowUp  `json:"follow_up" yaml:"follow_up"`

	Labels Labels `json:"labels" yaml:"labels"`

	Metadata Metadata `json:"metadata" yaml:"metadata"`

	// Exclusion is set when the case cannot be reconstructed exactly.
	Exclusion *Exclusion `json:"exclusion,omitempty" yaml:"exclusion,omitempty"`
}

type Repository struct {
	Owner string `json:"owner" yaml:"owner"`
	Name  string `json:"name" yaml:"name"`
	URL   string `json:"url" yaml:"url"`
}

type PullRequest struct {
	Number         int    `json:"number" yaml:"number"`
	BaseSHA        string `json:"base_sha" yaml:"base_sha"`
	InitialHeadSHA string `json:"initial_head_sha" yaml:"initial_head_sha"`
	FinalHeadSHA   string `json:"final_head_sha,omitempty" yaml:"final_head_sha,omitempty"`
	Title          string `json:"title,omitempty" yaml:"title,omitempty"`
}

type ReviewEvent struct {
	RoundIndex        int       `json:"round_index" yaml:"round_index"`
	Kind              string    `json:"kind" yaml:"kind"` // formal-review | inline-comment-cluster | issue-comment
	GitHubReviewIDs   []int64   `json:"github_review_ids" yaml:"github_review_ids"`
	ReviewedSHA       string    `json:"reviewed_sha" yaml:"reviewed_sha"`
	ReviewedSHASource string    `json:"reviewed_sha_source" yaml:"reviewed_sha_source"`
	SubmittedAt       time.Time `json:"submitted_at" yaml:"submitted_at"`
	Reviewers         []string  `json:"reviewers" yaml:"reviewers"`
	Dismissed         bool      `json:"dismissed" yaml:"dismissed"`
}

type EvidenceWindow struct {
	OpensAt         time.Time        `json:"opens_at" yaml:"opens_at"`
	ClosesAt        time.Time        `json:"closes_at,omitempty" yaml:"closes_at,omitempty"`
	CloseReason     string           `json:"close_reason,omitempty" yaml:"close_reason,omitempty"`
	FollowUpCommits []FollowUpCommit `json:"follow_up_commits" yaml:"follow_up_commits"`
}

type FollowUpCommit struct {
	SHA          string    `json:"sha" yaml:"sha"`
	PushedAt     time.Time `json:"pushed_at,omitempty" yaml:"pushed_at,omitempty"`
	ViaForcePush bool      `json:"via_force_push" yaml:"via_force_push"`
}

type Comment struct {
	ID                 int64     `json:"id" yaml:"id"`
	Kind               string    `json:"kind" yaml:"kind"` // review-comment | issue-comment | review-body
	URL                string    `json:"url,omitempty" yaml:"url,omitempty"`
	Author             string    `json:"author" yaml:"author"`
	Body               string    `json:"body" yaml:"body"`
	Path               string    `json:"path,omitempty" yaml:"path,omitempty"`
	Line               int       `json:"line,omitempty" yaml:"line,omitempty"`
	OriginalCommitID   string    `json:"original_commit_id,omitempty" yaml:"original_commit_id,omitempty"`
	CreatedAt          time.Time `json:"created_at" yaml:"created_at"`
	Classification     string    `json:"classification,omitempty" yaml:"classification,omitempty"`
	GeneralizedConcern string    `json:"generalized_concern,omitempty" yaml:"generalized_concern,omitempty"`
	ApprovedAsLabel    bool      `json:"approved_as_label" yaml:"approved_as_label"`
}

type FollowUp struct {
	Commits                []FollowUpCommit `json:"commits" yaml:"commits"`
	LikelyResolvedConcerns []string         `json:"likely_resolved_concerns,omitempty" yaml:"likely_resolved_concerns,omitempty"`
}

type Labels struct {
	ExpectedConcerns []ExpectedConcern `json:"expected_concerns" yaml:"expected_concerns"`
	KnownNonIssues   []string          `json:"known_non_issues,omitempty" yaml:"known_non_issues,omitempty"`
}

type ExpectedConcern struct {
	ID         string   `json:"id" yaml:"id"`
	Summary    string   `json:"summary" yaml:"summary"`
	Importance string   `json:"importance" yaml:"importance"` // high | medium | low
	Confidence string   `json:"confidence" yaml:"confidence"`
	Source     []string `json:"source" yaml:"source"`
	File       string   `json:"file,omitempty" yaml:"file,omitempty"`
	Approved   bool     `json:"approved" yaml:"approved"`
	// Scope relative to the owning adversary mission.
	// in_scope | out_of_scope | unclear — only in_scope should be graded as gold.
	Scope       string `json:"scope,omitempty" yaml:"scope,omitempty"`
	ScopeReason string `json:"scope_reason,omitempty" yaml:"scope_reason,omitempty"`
	ScopeMethod string `json:"scope_method,omitempty" yaml:"scope_method,omitempty"`
	// OwnerAdversary is the package id that should be graded on this concern
	// (e.g. go-concurrency, githubactions, engineering-review). Empty = none.
	OwnerAdversary string `json:"owner_adversary,omitempty" yaml:"owner_adversary,omitempty"`
	// ThreadContext contains bounded, same-thread conversation around the source
	// reviewer comment. It is interpretation evidence for routing and issue
	// abstraction only; it is never a gold concern and is not used by scoring.
	ThreadContext []ReviewThreadContext `json:"thread_context,omitempty" yaml:"thread_context,omitempty"`
	// ThreadDisposition records the final, deterministic disposition of the
	// complete inline discussion so local evidence can distinguish unresolved,
	// reiterated, withdrawn, and author-reported-fix threads.
	ThreadDisposition    string `json:"thread_disposition,omitempty" yaml:"thread_disposition,omitempty"`
	ThreadDispositionURL string `json:"thread_disposition_url,omitempty" yaml:"thread_disposition_url,omitempty"`
}

// ReviewThreadContext is a non-gold message adjacent to a reviewer concern.
// Role is explicit so model-backed stages cannot mistake a pull request author's
// explanation for a second human review finding.
type ReviewThreadContext struct {
	CommentID int64     `json:"comment_id" yaml:"comment_id"`
	URL       string    `json:"url,omitempty" yaml:"url,omitempty"`
	Author    string    `json:"author" yaml:"author"`
	Role      string    `json:"role" yaml:"role"` // reviewer | pull_request_author
	Body      string    `json:"body" yaml:"body"`
	CreatedAt time.Time `json:"created_at,omitempty" yaml:"created_at,omitempty"`
}

type Metadata struct {
	CreatedAt       time.Time `json:"created_at" yaml:"created_at"`
	ReviewedByHuman bool      `json:"reviewed_by_human" yaml:"reviewed_by_human"`
	Split           string    `json:"split" yaml:"split"` // discovery | validation | hidden | regression
}

type Exclusion struct {
	Reason string `json:"reason" yaml:"reason"`
	Detail string `json:"detail,omitempty" yaml:"detail,omitempty"`
}

// CaseID builds the stable identity: <repo>-pr-<n>-r<k>
func CaseID(repo string, pr, round int) string {
	return repo + "-pr-" + itoa(pr) + "-r" + itoa(round)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digs []byte
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		digs = append(digs, byte('0'+n%10))
		n /= 10
	}
	if neg {
		digs = append(digs, '-')
	}
	for i, j := 0, len(digs)-1; i < j; i, j = i+1, j-1 {
		digs[i], digs[j] = digs[j], digs[i]
	}
	return string(digs)
}
