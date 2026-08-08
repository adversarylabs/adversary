package results

import (
	"fmt"
	"strings"
)

// CommentSpirit is the review posture behind human gold (not just "defect").
type CommentSpirit string

const (
	SpiritShip     CommentSpirit = "ship-signal"    // OK to land / looks reasonable
	SpiritStyle    CommentSpirit = "style-nit"      // naming, formatting, taste
	SpiritDefect   CommentSpirit = "defect"         // correctness / safety / bug
	SpiritJudgment CommentSpirit = "technical-note" // design/API/clarity without pure LGTM
)

// MissDraftInput is enough human gold to write an agent-ready miss draft.
type MissDraftInput struct {
	Package  string
	Summary  string // human comment body/summary
	PRURL    string
	PRTitle  string
	CaseID   string
	File     string
	Line     int
	VoicePkg bool // person / broad generalist (e.g. torvalds)
}

// ClassifyCommentSpirit maps human text to a training spirit class.
func ClassifyCommentSpirit(summary string) CommentSpirit {
	s := strings.ToLower(strings.TrimSpace(summary))
	if s == "" {
		return SpiritJudgment
	}
	if isShipSignalText(s) && !hasUnresolvedReviewAsk(s) {
		return SpiritShip
	}
	// Explicit nit / style
	if strings.HasPrefix(strings.TrimSpace(s), "nit") ||
		strings.Contains(s, "nit:") || strings.Contains(s, "nit;") ||
		strings.Contains(s, "style") || strings.Contains(s, "rename") ||
		strings.Contains(s, "formatting") || strings.Contains(s, "whitespace") {
		// If also defect language, prefer defect
		if !looksLikeDefectText(s) {
			return SpiritStyle
		}
	}
	if looksLikeDefectText(s) {
		return SpiritDefect
	}
	return SpiritJudgment
}

// hasUnresolvedReviewAsk prevents qualified praise from becoming a ship signal.
// Reviewers commonly lead with "looks reasonable" and then state the blocking
// gap. The classifier cares about the unresolved clause, not the polite opener.
func hasUnresolvedReviewAsk(s string) bool {
	markers := []string{
		" but ", " however", " although", "please ", "needs ", "need to ",
		"must ", "should ", "could we ", "can we ", "before merge",
		"before landing", "not actually", "does not ", "doesn't ",
	}
	for _, marker := range markers {
		if strings.Contains(s, marker) {
			return true
		}
	}
	return false
}

func isShipSignalText(s string) bool {
	// Approval / "this is fine to land" — part of maintainer voice for person packages.
	markers := []string{
		"looks all reasonable", "looks reasonable", "looks fine", "looks good",
		"looks sane", "looks ok", "looks okay", "seems fine", "seems ok",
		"seems reasonable", "lgtm", "ship it", "i'd ship", "i would ship",
		"can merge", "you can merge", "fine to merge", "ok to merge",
		"patch looks sane", "patch is ok", "patch is fine", "all reasonable",
		"i'm fine with", "i am fine with", "no objections", "nothing blocking",
		"good enough", "ship it.",
	}
	for _, m := range markers {
		if strings.Contains(s, m) {
			return true
		}
	}
	// Short pure approval
	trim := strings.TrimSpace(s)
	if len(trim) < 40 {
		switch trim {
		case "ok", "okay", "fine", "good", "lgtm.", "lgtm!", "ship":
			return true
		}
	}
	return false
}

func looksLikeDefectText(s string) bool {
	keys := []string{
		"bug", "broken", "crash", "wrong", "incorrect", "leak", "race",
		"null", "nil", "panic", "overflow", "unsafe", "security",
		"will fail", "doesn't work", "does not work", "missing check",
		"off-by", "use-after", "double free", "buffer",
	}
	for _, k := range keys {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}

// BuildMissDraft writes a structured miss brief: spirit, when to post, variance rules.
// Human wording is an example of spirit only — never a fixed string to emit.
func BuildMissDraft(in MissDraftInput) string {
	spirit := ClassifyCommentSpirit(in.Summary)
	pkg := strings.TrimSpace(in.Package)
	if pkg == "" {
		pkg = "package"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "## Miss brief — package `%s`\n\n", pkg)
	fmt.Fprintf(&b, "### Human gold (example only — do not copy verbatim)\n\n")
	fmt.Fprintf(&b, "> %s\n\n", strings.TrimSpace(collapseWS(in.Summary)))
	if in.PRURL != "" {
		fmt.Fprintf(&b, "- PR: %s\n", in.PRURL)
	}
	if in.PRTitle != "" {
		fmt.Fprintf(&b, "- PR title: %s\n", in.PRTitle)
	}
	if in.CaseID != "" {
		fmt.Fprintf(&b, "- Case: `%s`\n", in.CaseID)
	}
	if in.File != "" {
		if in.Line > 0 {
			fmt.Fprintf(&b, "- Anchor: `%s:%d`\n", in.File, in.Line)
		} else {
			fmt.Fprintf(&b, "- Anchor: `%s`\n", in.File)
		}
	}
	fmt.Fprintf(&b, "\n### Spirit class: `%s`\n\n", spirit)
	fmt.Fprintf(&b, "%s\n\n", spiritExplain(spirit, in.VoicePkg))

	fmt.Fprintf(&b, "### When to post this class of feedback\n\n")
	for _, line := range whenToPost(spirit) {
		fmt.Fprintf(&b, "- %s\n", line)
	}
	fmt.Fprintf(&b, "\n### When **not** to post\n\n")
	for _, line := range whenNotToPost(spirit) {
		fmt.Fprintf(&b, "- %s\n", line)
	}

	fmt.Fprintf(&b, "\n### How to surface (implementation)\n\n")
	for _, line := range howToSurface(spirit) {
		fmt.Fprintf(&b, "- %s\n", line)
	}

	fmt.Fprintf(&b, "\n### Wording: keep spirit, vary surface form\n\n")
	fmt.Fprintf(&b, "The package must **not** hard-code the human sentence above in rules. ")
	if in.VoicePkg {
		fmt.Fprintf(&b, "Bank the human gold in **`%s`** (see Voice corpus section in the issue) ", VoiceBankFile)
		fmt.Fprintf(&b, "so CLI LLM rewrite can few-shot the persona. Same judgment, different words each run.\n\n")
	} else {
		fmt.Fprintf(&b, "For this policy/specialist package, keep the wording as training evidence only; do **not** append each concern to `%s`.\n\n", VoiceBankFile)
	}
	if in.VoicePkg {
		fmt.Fprintf(&b, "Synthetic phrasings in the same spirit (optional; real gold in voice.md is better):\n\n")
	} else {
		fmt.Fprintf(&b, "Possible paraphrases for the same reasoning class (evidence only, not voice-bank entries):\n\n")
	}
	for i, ex := range examplePhrasings(spirit, in.Summary) {
		fmt.Fprintf(&b, "%d. %q\n", i+1, ex)
	}
	fmt.Fprintf(&b, "\n")
	if in.VoicePkg {
		b.WriteString(FormatVoiceBankInstructions(in.Summary, spirit, in.PRURL))
	}
	fmt.Fprintf(&b, "\n### Acceptance for this train item\n\n")
	fmt.Fprintf(&b, "- [ ] On similar changes, the package emits this **class** of signal (not the exact quote)\n")
	fmt.Fprintf(&b, "- [ ] Posture matches **when to post** (no rubber-stamp on broken code; no silent ship on real bugs)\n")
	if in.VoicePkg {
		fmt.Fprintf(&b, "- [ ] **Human** gold excerpt appended under `%s` → `%s` (style few-shot only)\n", VoiceBankFile, VoiceBankSectionHeading(spirit))
		fmt.Fprintf(&b, "- [ ] Finding/opinion strings in `src/` stay generic; wording variance comes from voice rewrite\n")
	} else {
		fmt.Fprintf(&b, "- [ ] Human wording remains evidence only; `%s` is not expanded for this item\n", VoiceBankFile)
	}
	fmt.Fprintf(&b, "- [ ] Tests cover the **class**, not a single repository string match\n")
	return b.String()
}

func spiritExplain(s CommentSpirit, voicePkg bool) string {
	switch s {
	case SpiritShip:
		base := "This is a **maintainer ship / OK signal**: the human is saying the change is acceptable to land (sometimes with residual caveats)."
		if voicePkg {
			return base + " For a persona package (e.g. Torvalds-style), that *is* in-scope review behavior — not noise. The package should learn *when* to give a blunt positive judgment, not invent a fake bug."
		}
		return base + " Prefer modeling as opinion/positive, not a defect finding."
	case SpiritStyle:
		return "This is **style / taste / clarity** feedback (nits included for broad generalists). The package should raise similar taste issues when they match the persona, with evidence anchors when possible."
	case SpiritDefect:
		return "This is a **correctness / safety / real defect** concern. The package should surface an equivalent finding with evidence (file/line) on similar patterns."
	default:
		return "This is **technical judgment** (design, API, clarity, approach) that is not pure LGTM and not a classic bug keyword hit. Capture the concern class and when a maintainer would interrupt the author."
	}
}

func whenToPost(s CommentSpirit) []string {
	switch s {
	case SpiritShip:
		return []string{
			"You have actually reviewed the change (not a rubber stamp on an unread diff).",
			"No material correctness, safety, or data-loss issues remain in scope.",
			"You would land the change as a ruthless maintainer who owns the tree.",
			"Optional: residual nits exist but are non-blocking — say so separately or in the same voice.",
			"Use when a human maintainer would say “this is fine” / “ship it” rather than demand more work.",
		}
	case SpiritStyle:
		return []string{
			"The change introduces naming, structure, or style that fights surrounding code or the persona’s taste.",
			"The issue is real enough that a senior reviewer would comment (not pure bike-shed on every line).",
			"Prefer posting when the nit is in the changed lines or immediately adjacent.",
		}
	case SpiritDefect:
		return []string{
			"There is a plausible incorrect, unsafe, or incomplete behavior in the change.",
			"You can point at code (path/line) or a concrete scenario that fails.",
			"A careful human reviewer would block or demand a fix before merge.",
		}
	default:
		return []string{
			"The approach, API, layering, or clarity deserves maintainer pushback or guidance.",
			"The comment would change how the author finishes the work (not empty praise).",
			"Anchor to the relevant file when the human did.",
		}
	}
}

func whenNotToPost(s CommentSpirit) []string {
	switch s {
	case SpiritShip:
		return []string{
			"Material bugs, races, leaks, or broken error handling are still present.",
			"You only saw a green CI badge and did not inspect the change.",
			"The PR is WIP / explicitly not ready and the human was only acknowledging direction.",
			"Do not emit a low-severity “finding” that invents a problem just to have output.",
		}
	case SpiritStyle:
		return []string{
			"The surrounding code already uses the same pattern consistently.",
			"Fixing it would be pure churn with no readability win for this persona.",
		}
	case SpiritDefect:
		return []string{
			"The concern is speculative with no code path that can hit it.",
			"It is pure style dressed up as a bug.",
		}
	default:
		return []string{
			"Empty process comments, pure social chat, or bot noise.",
			"Repository-specific lore that does not generalize.",
		}
	}
}

func howToSurface(s CommentSpirit) []string {
	switch s {
	case SpiritShip:
		return []string{
			"Prefer `opinion.ship: true` (or equivalent) plus a short blunt summary in persona voice.",
			"Optional: a **positive** / observation note that the change is landable — not a defect finding.",
			"If residual nits exist, emit them as separate low-severity notes; do not cancel the ship signal.",
			"Wire voice rewrite so the summary is LLM-varied from `agent/voice.md`, not a constant string.",
		}
	case SpiritStyle:
		return []string{
			"Emit a low/info finding or observation with evidence on the line when possible.",
			"Title/summary should name the taste issue; body can be voice-rewritten.",
		}
	case SpiritDefect:
		return []string{
			"Emit a real finding with severity appropriate to impact, evidence, and recommendation.",
			"Match the *class* of bug (e.g. offset validation), not the exact human wording.",
		}
	default:
		return []string{
			"Finding or observation with enough detail that an author knows what to change.",
			"Voice rewrite for surface form; keep the technical claim stable.",
		}
	}
}

func examplePhrasings(s CommentSpirit, human string) []string {
	human = collapseWS(human)
	switch s {
	case SpiritShip:
		return []string{
			"Looks fine. I'd land this.",
			"Reasonable. Ship it.",
			"This is fine as far as I'm concerned.",
			"Patch is sane; merge when you're ready.",
			// one line that echoes spirit of the human without copying
			shortSpiritEcho(human, "Looks reasonable to me."),
		}
	case SpiritStyle:
		return []string{
			"Nit: this name is doing you no favors.",
			"Style: match the surrounding code or don't bother.",
			"This is harder to read than it needs to be.",
			shortSpiritEcho(human, "Nit on clarity here."),
		}
	case SpiritDefect:
		return []string{
			"This looks wrong — what happens on the empty/edge path?",
			"I don't buy this invariant; prove it or fix it.",
			"That check is incomplete.",
			shortSpiritEcho(human, "This needs a real fix, not a shrug."),
		}
	default:
		return []string{
			"Why this approach and not the boring one?",
			"I'm not convinced this belongs here.",
			"Explain the edge case or simplify.",
			shortSpiritEcho(human, "Walk me through why this is right."),
		}
	}
}

func shortSpiritEcho(human, fallback string) string {
	h := strings.TrimSpace(human)
	if h == "" {
		return fallback
	}
	// Soften into a non-identical example: truncate and rephrase prefix
	if len(h) > 90 {
		h = h[:90] + "…"
	}
	// Avoid presenting as the required string
	return "(spirit of) " + h
}

func collapseWS(s string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(s, "\r\n", "\n")), " ")
}
