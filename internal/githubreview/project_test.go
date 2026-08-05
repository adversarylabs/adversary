package githubreview

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/adversarylabs/adversary/pkg/review"
)

func TestProjectFindingsOnlyAndMinSeverity(t *testing.T) {
	line := 10
	env := review.RunEnvelope{
		ProtocolVersion: 1,
		Result: review.ReviewResult{
			Adversary:    review.ReviewAdversary{Name: "go-cli"},
			Target:       review.ReviewTarget{},
			Positives:    []review.Note{{Key: "p", Summary: "good"}},
			Observations: []review.Note{{Key: "o", Summary: "obs"}},
			Findings: []review.Finding{
				{ID: "f-high", Title: "High issue", Category: "c", Severity: "high", Confidence: "high", Summary: "S high", Evidence: []review.Evidence{{File: "a.go", Line: &line}}, Recommendation: "fix"},
				{ID: "f-low", Title: "Low issue", Category: "c", Severity: "low", Confidence: "high", Summary: "S low", Evidence: []review.Evidence{{File: "b.go", Line: &line}}},
			},
			Suppressed: review.Suppressed{},
			SuppressedFindings: []review.Finding{
				{ID: "f-sup", Title: "Suppressed", Category: "c", Severity: "high", Confidence: "high", Summary: "no", Evidence: []review.Evidence{}},
			},
		},
	}
	plan := ProjectFindings([]NamedEnvelope{{Adversary: "go-cli", Envelope: env}}, ProjectOptions{MinSeverity: "medium"})
	if plan.Summary.FindingsSeen != 2 {
		t.Fatalf("seen %d", plan.Summary.FindingsSeen)
	}
	if len(plan.Comments) != 1 || plan.Comments[0].FindingID != "f-high" {
		t.Fatalf("comments %#v", plan.Comments)
	}
	if len(plan.Skipped) != 1 || plan.Skipped[0].Reason != "below_min_severity" {
		t.Fatalf("skipped %#v", plan.Skipped)
	}
	// No observation/positive as comments
	for _, c := range plan.Comments {
		if strings.Contains(c.Body, "obs") || strings.Contains(strings.ToLower(c.Title), "good") {
			t.Fatal(c)
		}
	}
	if !strings.Contains(plan.Comments[0].Body, "adversary-review:v1") {
		t.Fatal(plan.Comments[0].Body)
	}
	raw, _ := json.Marshal(plan)
	if strings.Contains(string(raw), "f-sup") {
		t.Fatal("suppressed leaked into plan json")
	}
}

func TestNormalizePath(t *testing.T) {
	got, err := normalizeRepoRelativePath(`pkg\foo.go`)
	if err != nil || got != "pkg/foo.go" {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := normalizeRepoRelativePath("../x"); err == nil {
		t.Fatal("expected error")
	}
	if _, err := normalizeRepoRelativePath("/abs"); err == nil {
		t.Fatal("expected error")
	}
}
