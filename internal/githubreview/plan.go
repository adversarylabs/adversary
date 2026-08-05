package githubreview

import "github.com/adversarylabs/adversary/pkg/review"

// CommentPlan is a derived, comment-ready projection of review findings.
type CommentPlan struct {
	SchemaVersion int              `json:"schemaVersion"`
	Source        string           `json:"source"`
	Repository    string           `json:"repository,omitempty"`
	PullRequest   int              `json:"pullRequest,omitempty"`
	HeadSHA       string           `json:"headSha,omitempty"`
	MinSeverity   string           `json:"minSeverity,omitempty"`
	Voice         VoiceInfo        `json:"voice"`
	Comments      []PlannedComment `json:"comments"`
	Skipped       []SkippedFinding `json:"skipped,omitempty"`
	ReviewBody    string           `json:"reviewBody,omitempty"`
	Summary       PlanSummary      `json:"summary"`
}

// VoiceInfo records which prompt was used for LLM rewrite attempts.
type VoiceInfo struct {
	Source string `json:"source"` // cli_default | repo
	Path   string `json:"path,omitempty"`
}

// PlannedComment is one finding projected for a PR review thread or body.
type PlannedComment struct {
	FindingID       string `json:"findingId"`
	Adversary       string `json:"adversary"`
	Severity        string `json:"severity"`
	Confidence      string `json:"confidence"`
	Title           string `json:"title"`
	Body            string `json:"body"`
	BodySource      string `json:"bodySource"` // llm | template
	Anchor          Anchor `json:"anchor"`
	Placement       string `json:"placement"` // inline | review_body | unplaceable
	PlacementReason string `json:"placementReason,omitempty"`
}

// Anchor is the primary evidence location.
type Anchor struct {
	Path      string `json:"path"`
	Line      *int   `json:"line,omitempty"`
	EndLine   *int   `json:"endLine,omitempty"`
	Side      string `json:"side,omitempty"`
	StartSide string `json:"startSide,omitempty"`
	CommitOID string `json:"commitOid,omitempty"`
}

// SkippedFinding records why a finding was not planned as a thread.
type SkippedFinding struct {
	FindingID string `json:"findingId"`
	Adversary string `json:"adversary"`
	Reason    string `json:"reason"`
	Severity  string `json:"severity,omitempty"`
}

// PlanSummary counts for operators.
type PlanSummary struct {
	FindingsSeen  int    `json:"findingsSeen"`
	Comments      int    `json:"comments"`
	Inline        int    `json:"inline"`
	ReviewBody    int    `json:"reviewBody"`
	Unplaceable   int    `json:"unplaceable"`
	Skipped       int    `json:"skipped"`
	DiffValidated bool   `json:"diffValidated"`
	Notes         string `json:"notes,omitempty"`
}

// NamedEnvelope pairs a run result with its adversary ref.
type NamedEnvelope struct {
	Adversary string
	Envelope  review.RunEnvelope
}

// SeverityRank maps protocol severities to order.
func SeverityRank(s string) int {
	switch s {
	case "info":
		return 0
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	case "critical":
		return 4
	default:
		return -1
	}
}
