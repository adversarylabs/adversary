package judge

import (
	"strings"
	"unicode"

	"github.com/adversarylabs/adversary/internal/train/cases"
	"github.com/adversarylabs/adversary/internal/train/normalize"
)

// FindingJudgment is a structured judgment for one finding.
type FindingJudgment struct {
	FindingID              string `json:"finding_id"`
	Valid                  bool   `json:"valid"`
	Importance             string `json:"importance,omitempty"`
	SupportedByEvidence    bool   `json:"supported_by_evidence"`
	Actionable             bool   `json:"actionable"`
	DuplicateOf            string `json:"duplicate_of,omitempty"`
	MatchesExpectedConcern string `json:"matches_expected_concern,omitempty"`
	Reason                 string `json:"reason"`
}

// ReviewJudgment aggregates finding judgments and concern coverage.
type ReviewJudgment struct {
	ReviewerID           string            `json:"reviewer_id"`
	Findings             []FindingJudgment `json:"findings"`
	ExpectedMatched      []string          `json:"expected_matched"`
	ExpectedMissed       []string          `json:"expected_missed"`
	FalsePositiveCount   int               `json:"false_positive_count"`
	ImportantRecall      float64           `json:"important_concern_recall"`
	Precision            float64           `json:"precision"`
	UnsupportedClaimRate float64           `json:"unsupported_claim_rate"`
}

// JudgeReview matches normalized findings against approved expected concerns.
// This is a deterministic lexical/overlap judge for the first slice (no model required).
// Live model judging can wrap the same input/output schema later.
func JudgeReview(review *normalize.Review, expected []cases.ExpectedConcern) *ReviewJudgment {
	approved := cases.ApprovedLabels(expected)
	j := &ReviewJudgment{
		ReviewerID: review.ReviewerID,
		Findings:   make([]FindingJudgment, 0, len(review.Findings)),
	}
	matchedConcern := map[string]bool{}
	validCount := 0
	unsupported := 0

	for _, f := range review.Findings {
		fj := FindingJudgment{
			FindingID:           f.ID,
			SupportedByEvidence: strings.TrimSpace(f.Evidence) != "" || f.File != "",
			Actionable:          strings.TrimSpace(f.SuggestedFix) != "" || strings.TrimSpace(f.Claim) != "",
		}
		matchID, score := bestMatch(f, approved)
		if matchID != "" && score >= 0.25 {
			fj.Valid = true
			fj.MatchesExpectedConcern = matchID
			fj.Importance = importanceOf(approved, matchID)
			fj.Reason = "matches expected concern by token overlap"
			matchedConcern[matchID] = true
			validCount++
		} else if looksPlausibleEngineering(f) {
			// Not in gold set: count as potential FP for precision, but may still be valid engineering.
			fj.Valid = fj.SupportedByEvidence
			fj.Reason = "no gold match; validity based on evidence presence"
			// Unmatched finding is a false positive relative to the gold set either way.
			j.FalsePositiveCount++
			if !fj.Valid {
				unsupported++
			}
		} else {
			fj.Valid = false
			fj.Reason = "weak claim without gold match"
			j.FalsePositiveCount++
			unsupported++
		}
		j.Findings = append(j.Findings, fj)
	}

	for _, e := range approved {
		if matchedConcern[e.ID] {
			j.ExpectedMatched = append(j.ExpectedMatched, e.ID)
		} else {
			j.ExpectedMissed = append(j.ExpectedMissed, e.ID)
		}
	}

	important := 0
	importantHit := 0
	for _, e := range approved {
		if e.Importance == "high" || e.Importance == "medium" || e.Importance == "" {
			important++
			if matchedConcern[e.ID] {
				importantHit++
			}
		}
	}
	if important > 0 {
		j.ImportantRecall = float64(importantHit) / float64(important)
	}
	n := len(review.Findings)
	if n > 0 {
		j.Precision = float64(validCount) / float64(n)
		j.UnsupportedClaimRate = float64(unsupported) / float64(n)
	} else if len(approved) > 0 {
		j.Precision = 0
		j.ImportantRecall = 0
	}
	return j
}

func importanceOf(expected []cases.ExpectedConcern, id string) string {
	for _, e := range expected {
		if e.ID == id {
			return e.Importance
		}
	}
	return ""
}

func bestMatch(f normalize.Finding, expected []cases.ExpectedConcern) (string, float64) {
	claimTokens := tokens(f.Claim + " " + f.Evidence + " " + f.File)
	var bestID string
	var best float64
	for _, e := range expected {
		et := tokens(e.Summary + " " + e.File)
		s := jaccard(claimTokens, et)
		// Boost same-file.
		if e.File != "" && f.File != "" && strings.EqualFold(e.File, f.File) {
			s += 0.15
		}
		if s > best {
			best = s
			bestID = e.ID
		}
	}
	return bestID, best
}

func looksPlausibleEngineering(f normalize.Finding) bool {
	c := strings.ToLower(f.Claim)
	if len(strings.TrimSpace(c)) < 12 {
		return false
	}
	keywords := []string{"nil", "race", "leak", "error", "context", "cancel", "timeout", "security", "inject", "deadlock", "goroutine", "mutex", "panic", "resource", "close", "lock"}
	for _, k := range keywords {
		if strings.Contains(c, k) {
			return true
		}
	}
	return f.File != "" && f.Severity != "info"
}

func tokens(s string) map[string]struct{} {
	s = strings.ToLower(s)
	var b strings.Builder
	out := map[string]struct{}{}
	flush := func() {
		t := b.String()
		b.Reset()
		if len(t) < 3 {
			return
		}
		// drop stopwords
		switch t {
		case "the", "and", "for", "with", "that", "this", "from", "are", "was", "were", "not", "can", "may", "should", "must":
			return
		}
		out[t] = struct{}{}
	}
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		} else {
			flush()
		}
	}
	flush()
	return out
}

func jaccard(a, b map[string]struct{}) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	inter := 0
	for t := range a {
		if _, ok := b[t]; ok {
			inter++
		}
	}
	union := len(a) + len(b) - inter
	if union == 0 {
		return 0
	}
	return float64(inter) / float64(union)
}

// Failure is a concrete review failure for the failure list.
type Failure struct {
	CaseID     string `json:"case_id"`
	ReviewerID string `json:"reviewer_id"`
	Kind       string `json:"kind"` // missed-concern | false-positive | unsupported-claim
	Detail     string `json:"detail"`
	ConcernID  string `json:"concern_id,omitempty"`
	FindingID  string `json:"finding_id,omitempty"`
}

// ExtractFailures builds a concrete failure list from a judgment.
func ExtractFailures(caseID string, j *ReviewJudgment) []Failure {
	var out []Failure
	for _, id := range j.ExpectedMissed {
		out = append(out, Failure{
			CaseID:     caseID,
			ReviewerID: j.ReviewerID,
			Kind:       "missed-concern",
			Detail:     "expected concern not matched by any finding",
			ConcernID:  id,
		})
	}
	for _, fj := range j.Findings {
		if fj.MatchesExpectedConcern != "" {
			continue
		}
		if !fj.Valid {
			out = append(out, Failure{
				CaseID:     caseID,
				ReviewerID: j.ReviewerID,
				Kind:       "unsupported-claim",
				Detail:     fj.Reason,
				FindingID:  fj.FindingID,
			})
		} else {
			out = append(out, Failure{
				CaseID:     caseID,
				ReviewerID: j.ReviewerID,
				Kind:       "false-positive",
				Detail:     "finding did not match gold expected concerns",
				FindingID:  fj.FindingID,
			})
		}
	}
	return out
}
