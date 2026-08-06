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
		"agent/voice.md",
		"Example maintainer comments",
		"Ship / OK",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in:\n%s", want, body[:min(1200, len(body))])
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
	body := formatIssueBody(r, "/pkg/docs/train-drafts/01839890.md", "/pkg")
	if !strings.Contains(body, "When to post") {
		t.Fatalf("expected rebuilt brief:\n%s", body[:900])
	}
	if !strings.Contains(body, "agent/voice.md") {
		t.Fatalf("expected voice bank path:\n%s", body[:1200])
	}
	if !strings.Contains(body, "Exact entry to add") {
		t.Fatalf("expected exact markdown entry for voice bank:\n%s", body[min(0, len(body)):min(2000, len(body))])
	}
	if !strings.Contains(body, "docs/train-drafts/01839890.md") {
		t.Fatalf("expected relative draft path, got:\n%s", body[len(body)-400:])
	}
	if !strings.Contains(body, "ship") {
		t.Fatalf("expected ship spirit:\n%s", body[:900])
	}
}

func TestFormatVoiceBankInstructions(t *testing.T) {
	s := FormatVoiceBankInstructions(
		"Ugh. This is nasty. The 'S' will also trigger on 'STRING'.",
		SpiritJudgment,
		"https://github.com/subsurface/libdc/pull/39",
	)
	for _, want := range []string{
		"agent/voice.md",
		"Example maintainer comments (style only)",
		"Design / technical judgment",
		"Ugh. This is nasty",
		"libdc/pull/39",
		"Never emit an example quote unchanged",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in:\n%s", want, s)
		}
	}
}
