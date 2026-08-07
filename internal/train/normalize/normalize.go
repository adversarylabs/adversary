package normalize

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Finding is the canonical per-finding schema used by judges.
type Finding struct {
	ID           string `json:"id"`
	File         string `json:"file,omitempty"`
	LineStart    int    `json:"line_start,omitempty"`
	LineEnd      int    `json:"line_end,omitempty"`
	Severity     string `json:"severity"`
	Category     string `json:"category"`
	Claim        string `json:"claim"`
	Evidence     string `json:"evidence,omitempty"`
	SuggestedFix string `json:"suggested_fix,omitempty"`
}

// Review is a normalized review.
type Review struct {
	ReviewerID string    `json:"reviewer_id"`
	Summary    string    `json:"summary,omitempty"`
	Findings   []Finding `json:"findings"`
	Source     string    `json:"source"` // adversary | baseline | fixture
}

// AdversaryEnvelope is a subset of the adversary review JSON envelope.
type AdversaryEnvelope struct {
	ProtocolVersion int `json:"protocolVersion"`
	Result          struct {
		Adversary struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"adversary"`
		Findings []struct {
			ID             string `json:"id"`
			Title          string `json:"title"`
			Category       string `json:"category"`
			Severity       string `json:"severity"`
			Summary        string `json:"summary"`
			Recommendation string `json:"recommendation"`
			Evidence       []struct {
				File    string `json:"file"`
				Line    int    `json:"line"`
				EndLine int    `json:"endLine"`
				Message string `json:"message"`
				Snippet string `json:"snippet"`
			} `json:"evidence"`
		} `json:"findings"`
		Notes []struct {
			Key     string `json:"key"`
			Summary string `json:"summary"`
		} `json:"notes"`
	} `json:"result"`
}

// BaselineReview is a simple baseline output shape.
type BaselineReview struct {
	Summary  string `json:"summary"`
	Findings []struct {
		ID       string `json:"id"`
		File     string `json:"file"`
		Line     int    `json:"line"`
		Severity string `json:"severity"`
		Category string `json:"category"`
		Claim    string `json:"claim"`
		Evidence string `json:"evidence"`
		Fix      string `json:"fix"`
	} `json:"findings"`
}

// FromAdversaryJSON normalizes an adversary CLI JSON envelope.
func FromAdversaryJSON(reviewerID string, raw []byte) (*Review, error) {
	var env AdversaryEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		// Try bare result object
		var resultOnly struct {
			Findings []struct {
				ID             string `json:"id"`
				Title          string `json:"title"`
				Category       string `json:"category"`
				Severity       string `json:"severity"`
				Summary        string `json:"summary"`
				Recommendation string `json:"recommendation"`
				Evidence       []struct {
					File    string `json:"file"`
					Line    int    `json:"line"`
					EndLine int    `json:"endLine"`
					Message string `json:"message"`
					Snippet string `json:"snippet"`
				} `json:"evidence"`
			} `json:"findings"`
		}
		if err2 := json.Unmarshal(raw, &resultOnly); err2 != nil {
			return nil, fmt.Errorf("adversary json: %w", err)
		}
		env.Result.Findings = resultOnly.Findings
	}
	r := &Review{
		ReviewerID: stripToolIdentity(reviewerID),
		Source:     "adversary",
		Findings:   make([]Finding, 0, len(env.Result.Findings)),
	}
	for _, f := range env.Result.Findings {
		nf := Finding{
			ID:           f.ID,
			Severity:     normalizeSeverity(f.Severity),
			Category:     f.Category,
			Claim:        firstNonEmpty(f.Summary, f.Title),
			SuggestedFix: f.Recommendation,
		}
		if len(f.Evidence) > 0 {
			e := f.Evidence[0]
			nf.File = e.File
			nf.LineStart = e.Line
			nf.LineEnd = e.EndLine
			nf.Evidence = firstNonEmpty(e.Message, e.Snippet)
		}
		// Strip tool-identifying prefixes from claims.
		nf.Claim = stripToolIdentity(nf.Claim)
		r.Findings = append(r.Findings, nf)
	}
	return r, nil
}

// FromBaselineJSON normalizes baseline reviewer output.
func FromBaselineJSON(raw []byte) (*Review, error) {
	var b BaselineReview
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, err
	}
	r := &Review{
		ReviewerID: "generic-baseline",
		Summary:    stripToolIdentity(b.Summary),
		Source:     "baseline",
		Findings:   make([]Finding, 0, len(b.Findings)),
	}
	for _, f := range b.Findings {
		r.Findings = append(r.Findings, Finding{
			ID:           f.ID,
			File:         f.File,
			LineStart:    f.Line,
			Severity:     normalizeSeverity(f.Severity),
			Category:     f.Category,
			Claim:        stripToolIdentity(f.Claim),
			Evidence:     f.Evidence,
			SuggestedFix: f.Fix,
		})
	}
	return r, nil
}

// FromAnyJSON tries multi-run CLI output (composition), then single adversary
// envelope, then baseline.
func FromAnyJSON(reviewerID string, raw []byte) (*Review, error) {
	if r, err := FromMultiRunJSON(reviewerID, raw); err == nil {
		return r, nil
	}
	if r, err := FromAdversaryJSON(reviewerID, raw); err == nil && (len(r.Findings) > 0 || strings.Contains(string(raw), "protocolVersion")) {
		return r, nil
	}
	if r, err := FromBaselineJSON(raw); err == nil {
		r.ReviewerID = stripToolIdentity(reviewerID)
		return r, nil
	}
	return FromAdversaryJSON(reviewerID, raw)
}

// FromMultiRunJSON merges CLI multi-adversary JSON (composition expand) into one
// review under reviewerID. Accepts either a bare {"results":[...]} object or the
// cmd writeJSON envelope {"command":"run","data":{"results":[...]}}.
func FromMultiRunJSON(reviewerID string, raw []byte) (*Review, error) {
	type item struct {
		Adversary string          `json:"adversary"`
		Output    json.RawMessage `json:"output"`
		Error     string          `json:"error"`
	}
	var results []item

	var envelope struct {
		Data *struct {
			Results []item `json:"results"`
		} `json:"data"`
		Results []item `json:"results"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, err
	}
	switch {
	case envelope.Data != nil && len(envelope.Data.Results) > 0:
		results = envelope.Data.Results
	case len(envelope.Results) > 0:
		results = envelope.Results
	default:
		return nil, fmt.Errorf("not multi-run json")
	}

	merged := &Review{
		ReviewerID: stripToolIdentity(reviewerID),
		Source:     "adversary",
		Findings:   nil,
	}
	// Prefer multi only when there are 2+ members or at least one nested output —
	// a single empty results array is not multi.
	gotAny := false
	for _, it := range results {
		if len(it.Output) == 0 {
			continue
		}
		part, err := FromAdversaryJSON(reviewerID, it.Output)
		if err != nil {
			// Nested output may itself be wrapped; try again via protocol strip.
			continue
		}
		gotAny = true
		for _, f := range part.Findings {
			// Prefix id when colliding across members.
			if it.Adversary != "" && f.ID != "" {
				f.ID = it.Adversary + "/" + f.ID
			}
			merged.Findings = append(merged.Findings, f)
		}
	}
	if !gotAny && len(results) < 2 {
		return nil, fmt.Errorf("not multi-run json")
	}
	// Multi with only errors still counts as multi product result (zero findings).
	if len(results) >= 2 || gotAny {
		return merged, nil
	}
	return nil, fmt.Errorf("not multi-run json")
}

func normalizeSeverity(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "info", "low", "medium", "high", "critical":
		return s
	case "error", "sev-high":
		return "high"
	case "warn", "warning":
		return "medium"
	default:
		if s == "" {
			return "medium"
		}
		return s
	}
}

func stripToolIdentity(s string) string {
	// Remove common tool banners that would deanonymize pairwise judges.
	repl := []string{
		"Engineering Review:",
		"engineering-review:",
		"[engineering-review]",
		"CodeRabbit:",
		"Greptile:",
		"Generated by Adversary",
	}
	out := s
	for _, p := range repl {
		out = strings.ReplaceAll(out, p, "")
	}
	return strings.TrimSpace(out)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// ToJSON serializes a normalized review.
func ToJSON(r *Review) ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}
