package normalize

import (
	"bytes"
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
	if r, recognized, err := fromMultiRunJSON(reviewerID, raw); recognized {
		return r, err
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
	r, recognized, err := fromMultiRunJSON(reviewerID, raw)
	if !recognized {
		return nil, fmt.Errorf("not multi-run json")
	}
	return r, err
}

type multiRunItem struct {
	Adversary string          `json:"adversary"`
	Output    json.RawMessage `json:"output"`
	Error     string          `json:"error"`
}

// fromMultiRunJSON distinguishes "not this shape" from "recognized but
// incomplete". Once composition output is recognized, callers must not fall
// back to a permissive single-review parser: doing so would turn member
// failures into an empty successful review and manufacture train misses.
func fromMultiRunJSON(reviewerID string, raw []byte) (*Review, bool, error) {
	results, recognized, err := decodeMultiRunItems(raw)
	if !recognized {
		return nil, false, err
	}
	if err != nil {
		return nil, true, err
	}
	if len(results) == 0 {
		return nil, true, fmt.Errorf("composition review contains no members")
	}

	merged := &Review{
		ReviewerID: stripToolIdentity(reviewerID),
		Source:     "adversary",
		Findings:   []Finding{},
	}
	for i, it := range results {
		member := strings.TrimSpace(it.Adversary)
		if member == "" {
			member = fmt.Sprintf("member %d", i+1)
		}
		if msg := strings.TrimSpace(it.Error); msg != "" {
			return nil, true, fmt.Errorf("composition review failed for %s: %s", member, msg)
		}
		output := bytes.TrimSpace(it.Output)
		if len(output) == 0 || bytes.Equal(output, []byte("null")) {
			return nil, true, fmt.Errorf("composition review missing output for %s", member)
		}
		if !isAdversaryReviewJSON(output) {
			return nil, true, fmt.Errorf("composition review returned invalid output for %s", member)
		}
		part, err := FromAdversaryJSON(reviewerID, output)
		if err != nil {
			return nil, true, fmt.Errorf("composition review could not parse output for %s: %w", member, err)
		}
		for _, f := range part.Findings {
			// Prefix id when colliding across members.
			if it.Adversary != "" && f.ID != "" {
				f.ID = it.Adversary + "/" + f.ID
			}
			merged.Findings = append(merged.Findings, f)
		}
	}
	return merged, true, nil
}

func decodeMultiRunItems(raw []byte) ([]multiRunItem, bool, error) {
	var envelope struct {
		Command string          `json:"command"`
		Data    json.RawMessage `json:"data"`
		Results json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, false, err
	}

	resultsRaw := envelope.Results
	recognized := len(resultsRaw) > 0
	if strings.EqualFold(strings.TrimSpace(envelope.Command), "run") {
		recognized = true
		var data struct {
			Results json.RawMessage `json:"results"`
		}
		if len(bytes.TrimSpace(envelope.Data)) == 0 || bytes.Equal(bytes.TrimSpace(envelope.Data), []byte("null")) {
			return nil, true, fmt.Errorf("composition run envelope is missing data")
		}
		if err := json.Unmarshal(envelope.Data, &data); err != nil {
			return nil, true, fmt.Errorf("composition run data: %w", err)
		}
		if len(data.Results) == 0 {
			return nil, true, fmt.Errorf("composition run envelope is missing results")
		}
		resultsRaw = data.Results
	}
	if !recognized {
		return nil, false, nil
	}

	var results []multiRunItem
	if err := json.Unmarshal(resultsRaw, &results); err != nil {
		return nil, true, fmt.Errorf("composition results: %w", err)
	}
	return results, true, nil
}

func isAdversaryReviewJSON(raw []byte) bool {
	var shape struct {
		ProtocolVersion int             `json:"protocolVersion"`
		Result          json.RawMessage `json:"result"`
		Findings        json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal(raw, &shape); err != nil {
		return false
	}
	result := bytes.TrimSpace(shape.Result)
	findings := bytes.TrimSpace(shape.Findings)
	hasResult := len(result) > 0 && !bytes.Equal(result, []byte("null")) && result[0] == '{'
	hasFindings := len(findings) > 0 && !bytes.Equal(findings, []byte("null")) && findings[0] == '['
	return (shape.ProtocolVersion > 0 && hasResult) || hasFindings
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
