// Package detection defines the stable data contract used to decide whether an
// adversary applies to a repository change. Detection is intentionally separate
// from review output: a detector selects work, it never emits findings.
package detection

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
)

const SchemaVersion = "adversary.detection.v1"

type Confidence string

const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

func ParseConfidence(value string) (Confidence, error) {
	confidence := Confidence(strings.ToLower(strings.TrimSpace(value)))
	if !confidence.Valid() {
		return "", fmt.Errorf("unsupported detection confidence %q (supported: low, medium, high)", value)
	}
	return confidence, nil
}

func (c Confidence) Valid() bool {
	return c == ConfidenceLow || c == ConfidenceMedium || c == ConfidenceHigh
}

func (c Confidence) Rank() int {
	switch c {
	case ConfidenceHigh:
		return 3
	case ConfidenceMedium:
		return 2
	case ConfidenceLow:
		return 1
	default:
		return 0
	}
}

type ChangeMode string

const (
	ModeDirtyWorktree    ChangeMode = "dirty-worktree"
	ModeBranchComparison ChangeMode = "branch-comparison"
	ModeExplicitRange    ChangeMode = "explicit-range"
	ModePullRequest      ChangeMode = "pull-request"
)

type ChangedFileStatus string

const (
	StatusAdded     ChangedFileStatus = "added"
	StatusModified  ChangedFileStatus = "modified"
	StatusDeleted   ChangedFileStatus = "deleted"
	StatusRenamed   ChangedFileStatus = "renamed"
	StatusCopied    ChangedFileStatus = "copied"
	StatusUntracked ChangedFileStatus = "untracked"
)

type ChangedFile struct {
	Path         string            `json:"path"`
	PreviousPath string            `json:"previousPath,omitempty"`
	Status       ChangedFileStatus `json:"status"`
	Additions    *int              `json:"additions,omitempty"`
	Deletions    *int              `json:"deletions,omitempty"`
}

type Context struct {
	SchemaVersion   string        `json:"schemaVersion"`
	RepositoryRoot  string        `json:"repositoryRoot"`
	Mode            ChangeMode    `json:"mode"`
	BaseRef         string        `json:"baseRef,omitempty"`
	HeadRef         string        `json:"headRef,omitempty"`
	MergeBase       string        `json:"mergeBase,omitempty"`
	ChangedFiles    []ChangedFile `json:"changedFiles"`
	RepositoryFiles []string      `json:"repositoryFiles,omitempty"`
}

type Result struct {
	SchemaVersion   string     `json:"schemaVersion"`
	Applicable      bool       `json:"applicable"`
	Confidence      Confidence `json:"confidence"`
	Reasons         []string   `json:"reasons"`
	RelevantFiles   []string   `json:"relevantFiles,omitempty"`
	RepositoryMatch *bool      `json:"repositoryMatch,omitempty"`
	ChangeMatch     *bool      `json:"changeMatch,omitempty"`
}

func (r Result) Validate() error {
	if r.SchemaVersion != SchemaVersion {
		return fmt.Errorf("detection result schemaVersion must be %q", SchemaVersion)
	}
	if !r.Confidence.Valid() {
		return fmt.Errorf("detection result confidence %q is unsupported", r.Confidence)
	}
	if len(r.Reasons) == 0 {
		return fmt.Errorf("detection result must include at least one reason")
	}
	for i, reason := range r.Reasons {
		if strings.TrimSpace(reason) == "" || reason != strings.TrimSpace(reason) {
			return fmt.Errorf("detection result reasons[%d] must be non-empty and normalized", i)
		}
		if strings.IndexFunc(reason, unicode.IsControl) >= 0 {
			return fmt.Errorf("detection result reasons[%d] must not contain control characters", i)
		}
	}
	for i, path := range r.RelevantFiles {
		if strings.TrimSpace(path) == "" || path != strings.TrimSpace(path) {
			return fmt.Errorf("detection result relevantFiles[%d] must be non-empty and normalized", i)
		}
		if strings.IndexFunc(path, unicode.IsControl) >= 0 {
			return fmt.Errorf("detection result relevantFiles[%d] must not contain control characters", i)
		}
	}
	return nil
}

// Normalize makes explanatory output deterministic without changing the
// detector's selection decision.
func (r *Result) Normalize() {
	r.Reasons = sortedUnique(r.Reasons)
	r.RelevantFiles = sortedUnique(r.RelevantFiles)
}

func sortedUnique(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
