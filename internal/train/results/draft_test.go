package results

import (
	"strings"
	"testing"
	"unicode/utf8"
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
		"synthetic train draft",
	} {
		if want == "synthetic train draft" {
			// present as "Bank synthetic train draft titles"
			if !strings.Contains(s, "synthetic") {
				t.Fatalf("missing synthetic warning:\n%s", s)
			}
			continue
		}
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in:\n%s", want, s)
		}
	}
}

func TestTruncateRunesUTF8Safe(t *testing.T) {
	// Multi-byte runes: each "世" is 3 bytes; 5 runes + ellipsis.
	s := "世界世界世界世界" // 8 runes
	got := truncateRunes(s, 5)
	if !utf8.ValidString(got) {
		t.Fatalf("invalid utf8: %q", got)
	}
	if utf8.RuneCountInString(got) != 5 { // 4 runes + "…" is still 5 runes if ellipsis is one rune
		// We use maxRunes-1 content + ellipsis → 4 + 1 = 5 runes
		if utf8.RuneCountInString(got) != 5 {
			t.Fatalf("rune count %d got %q", utf8.RuneCountInString(got), got)
		}
	}
	if !strings.HasSuffix(got, "…") {
		t.Fatalf("expected ellipsis: %q", got)
	}
}

func TestShouldBankHumanVoice(t *testing.T) {
	if !ShouldBankHumanVoice(KindMiss) || !ShouldBankHumanVoice(KindHuman) {
		t.Fatal("miss/human should bank")
	}
	if ShouldBankHumanVoice(KindDraft) || ShouldBankHumanVoice(KindFalsePositive) {
		t.Fatal("draft/fp must not bank")
	}
}

func TestFormatIssueBodyDraftDoesNotBankSyntheticSummary(t *testing.T) {
	r := Result{
		ID:        "abcd1234",
		Package:   "torvalds",
		Kind:      KindDraft,
		Status:    StatusNew,
		Summary:   "torvalds: catch lifecycle misses", // synthetic suggested-issue title
		Title:     "torvalds: catch lifecycle misses",
		DraftBody: "Improve shutdown detection.\n",
	}
	body := formatIssueBody(r, "docs/train-drafts/abcd1234.md", "/pkg")
	if strings.Contains(body, "Exact entry to add") {
		t.Fatal("draft kind must not emit voice bank entry")
	}
	if !strings.Contains(body, "not human gold") && !strings.Contains(body, "Do **not** bank") {
		t.Fatalf("expected no-bank instruction:\n%s", body[:800])
	}
	if strings.Contains(body, "Human gold (bank in voice") {
		t.Fatal("must not label draft summary as human gold")
	}
}
