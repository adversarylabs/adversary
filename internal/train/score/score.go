package score

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"github.com/adversarylabs/adversary/internal/train/judge"
	"github.com/adversarylabs/adversary/internal/train/securefs"
)

// Scorecard summarizes reviewer quality on a case set.
type Scorecard struct {
	ReviewerID             string          `json:"reviewer_id"`
	GeneratedAt            time.Time       `json:"generated_at"`
	CaseCount              int             `json:"case_count"`
	ImportantConcernRecall float64         `json:"important_concern_recall"`
	Precision              float64         `json:"precision"`
	FalsePositiveRate      float64         `json:"false_positive_rate"`
	UnsupportedClaimRate   float64         `json:"unsupported_claim_rate"`
	FailureCount           int             `json:"failure_count"`
	Failures               []judge.Failure `json:"failures"`
	PerCase                []CaseScore     `json:"per_case"`
}

// CaseScore is per-case metrics.
type CaseScore struct {
	CaseID                 string  `json:"case_id"`
	ImportantConcernRecall float64 `json:"important_concern_recall"`
	Precision              float64 `json:"precision"`
	FalsePositiveCount     int     `json:"false_positive_count"`
}

// Aggregate builds a scorecard from per-case judgments and failures.
func Aggregate(reviewerID string, judgments map[string]*judge.ReviewJudgment, failures []judge.Failure) *Scorecard {
	sc := &Scorecard{
		ReviewerID:   reviewerID,
		GeneratedAt:  time.Now().UTC(),
		Failures:     failures,
		FailureCount: len(failures),
	}
	if len(judgments) == 0 {
		return sc
	}
	var sumRecall, sumPrec, sumUnsup float64
	var sumFP, sumFindings int
	for caseID, j := range judgments {
		sc.CaseCount++
		sumRecall += j.ImportantRecall
		sumPrec += j.Precision
		sumUnsup += j.UnsupportedClaimRate
		sumFP += j.FalsePositiveCount
		sumFindings += len(j.Findings)
		sc.PerCase = append(sc.PerCase, CaseScore{
			CaseID:                 caseID,
			ImportantConcernRecall: j.ImportantRecall,
			Precision:              j.Precision,
			FalsePositiveCount:     j.FalsePositiveCount,
		})
	}
	n := float64(sc.CaseCount)
	sc.ImportantConcernRecall = sumRecall / n
	sc.Precision = sumPrec / n
	sc.UnsupportedClaimRate = sumUnsup / n
	if sumFindings > 0 {
		sc.FalsePositiveRate = float64(sumFP) / float64(sumFindings)
	}
	return sc
}

// FormatText renders a human-readable scorecard.
func FormatText(sc *Scorecard) string {
	return fmt.Sprintf(`%s

Cases:                         %d
Important issue recall:      %5.1f%%
Precision:                   %5.1f%%
False-positive rate:         %5.1f%%
Unsupported-claim rate:      %5.1f%%
Concrete failures listed:      %d
`,
		sc.ReviewerID,
		sc.CaseCount,
		sc.ImportantConcernRecall*100,
		sc.Precision*100,
		sc.FalsePositiveRate*100,
		sc.UnsupportedClaimRate*100,
		sc.FailureCount,
	)
}

// Save writes scorecard JSON and text.
func Save(dir string, sc *Scorecard) error {
	if err := securefs.MkdirAll(dir); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(sc, "", "  ")
	if err != nil {
		return err
	}
	if err := securefs.WriteFile(filepath.Join(dir, "scorecard.json"), raw); err != nil {
		return err
	}
	if err := securefs.WriteFile(filepath.Join(dir, "scorecard.txt"), []byte(FormatText(sc))); err != nil {
		return err
	}
	failRaw, err := json.MarshalIndent(sc.Failures, "", "  ")
	if err != nil {
		return err
	}
	return securefs.WriteFile(filepath.Join(dir, "failures.json"), failRaw)
}
