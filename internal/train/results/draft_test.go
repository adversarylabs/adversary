package results

import (
	"strings"
	"testing"
)

func TestClassifyShipSignal(t *testing.T) {
	if ClassifyCommentSpirit("Looks all reasonable to me") != SpiritShip {
		t.Fatal("expected ship")
	}
	if ClassifyCommentSpirit("Is this offset actually guaranteed to be there?") != SpiritDefect &&
		ClassifyCommentSpirit("Is this offset actually guaranteed to be there?") != SpiritJudgment {
		t.Fatal("expected defect or judgment")
	}
	if ClassifyCommentSpirit("nit: rename this variable") != SpiritStyle {
		t.Fatal("expected style")
	}
}

func TestBuildMissDraftShipHasWhenAndVariance(t *testing.T) {
	body := BuildMissDraft(MissDraftInput{
		Package:  "torvalds",
		Summary:  "Looks all reasonable to me",
		PRURL:    "https://github.com/subsurface/libdc/pull/71",
		PRTitle:  "Update libdivecomputer from Upstream.",
		CaseID:   "libdc-pr-71-r1",
		VoicePkg: true,
	})
	for _, want := range []string{
		"ship-signal",
		"When to post",
		"When **not** to post",
		"do not copy verbatim",
		"opinion.ship",
		"Looks fine",
		"libdc/pull/71",
		"fake bug",
		"LLM/voice rewrite",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in:\n%s", want, body[:min(900, len(body))])
		}
	}
}

func TestFormatIssueBodyRebuildsLegacyThinDraft(t *testing.T) {
	r := Result{
		ID:        "01839890",
		Package:   "torvalds",
		Kind:      KindMiss,
		Status:    StatusNew,
		Summary:   "Looks all reasonable to me",
		Title:     "Looks all reasonable to me",
		PRURL:     "https://github.com/subsurface/libdc/pull/71",
		DraftBody: "## Miss\n\nLooks all reasonable to me\n", // legacy thin
	}
	body := formatIssueBody(r, "/tmp/draft.md")
	if !strings.Contains(body, "When to post") {
		t.Fatalf("expected rebuilt brief:\n%s", body[:900])
	}
	if !strings.Contains(body, "do **not** hard-code") && !strings.Contains(body, "Do not** hard-code") && !strings.Contains(body, "Do not") {
		t.Fatalf("expected variance instruction:\n%s", body[:900])
	}
	if !strings.Contains(body, "ship") {
		t.Fatalf("expected ship spirit:\n%s", body[:900])
	}
}
