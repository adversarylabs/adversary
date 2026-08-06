package results

import (
	"fmt"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// Voice example bank paths (package-relative). Prefer voice.md so CLI rewrite
// already loads them via ResolveVoice (agent/voice.md).
const (
	VoiceBankFile    = "agent/voice.md"
	VoiceBankHeading = "## Example maintainer comments (style only)"
)

// VoiceBankSectionHeading is the per-spirit subsection under VoiceBankHeading.
func VoiceBankSectionHeading(spirit CommentSpirit) string {
	switch spirit {
	case SpiritShip:
		return "### Ship / OK"
	case SpiritStyle:
		return "### Nits / style"
	case SpiritDefect:
		return "### Defects / correctness"
	default:
		return "### Design / technical judgment"
	}
}

// ShouldBankHumanVoice is true only for rows that carry real human review text.
// KindDraft / false-positive summaries are synthetic and must not pollute the corpus.
func ShouldBankHumanVoice(kind string) bool {
	switch normalizeKind(kind) {
	case KindMiss, KindHuman:
		return true
	default:
		return false
	}
}

// truncateRunes trims s to at most maxRunes runes without splitting UTF-8 sequences.
func truncateRunes(s string, maxRunes int) string {
	if maxRunes <= 0 || s == "" {
		return ""
	}
	if utf8.RuneCountInString(s) <= maxRunes {
		return s
	}
	// Leave room for ellipsis when truncating.
	n := maxRunes - 1
	if n < 1 {
		n = maxRunes
	}
	i := 0
	for range n {
		_, size := utf8.DecodeRuneInString(s[i:])
		i += size
	}
	return s[:i] + "…"
}

// FormatVoiceBankInstructions tells the implementer exactly where and how to
// bank this human gold so CLI LLM rewrite can use it as few-shot style.
// summary must be real human review text (not a generated draft title).
func FormatVoiceBankInstructions(summary string, spirit CommentSpirit, prURL string) string {
	quote := strings.TrimSpace(collapseWS(summary))
	if quote == "" {
		quote = "(no human text stored)"
	}
	// Keep bank entries short for agent/voice.md size limits (CLI max ~32KiB).
	quote = truncateRunes(quote, 280)

	var b strings.Builder
	fmt.Fprintf(&b, "### Voice corpus (required for persona packages)\n\n")
	fmt.Fprintf(&b, "Detection teaches *when* to fire. **Wording spirit** lives in the package voice file ")
	fmt.Fprintf(&b, "so the CLI can few-shot rewrite comments without hard-coding strings in rules.\n\n")
	fmt.Fprintf(&b, "**File to edit (package root, create if missing):** `%s`\n\n", VoiceBankFile)
	fmt.Fprintf(&b, "**What to do:**\n\n")
	fmt.Fprintf(&b, "1. Ensure this heading exists near the end of the file (after core voice rules):\n\n")
	fmt.Fprintf(&b, "```markdown\n%s\n\n", VoiceBankHeading)
	fmt.Fprintf(&b, "These are **real maintainer comments used as style few-shots only**.\n")
	fmt.Fprintf(&b, "When rewriting findings: match cadence and bluntness; re-ground every claim\n")
	fmt.Fprintf(&b, "in the *current* finding evidence. Never invent facts from these examples.\n")
	fmt.Fprintf(&b, "Never emit an example quote unchanged as the PR comment body.\n")
	fmt.Fprintf(&b, "```\n\n")
	fmt.Fprintf(&b, "2. Under that heading, ensure the spirit subsection exists:\n\n")
	fmt.Fprintf(&b, "```markdown\n%s\n```\n\n", VoiceBankSectionHeading(spirit))
	fmt.Fprintf(&b, "3. **Append** this **human** gold as one blockquote (dedupe if the same text is already present).\n")
	fmt.Fprintf(&b, "   Optional one-line source note on the line after the quote.\n\n")
	fmt.Fprintf(&b, "**Exact entry to add under `%s` → `%s`:**\n\n", VoiceBankFile, VoiceBankSectionHeading(spirit))
	fmt.Fprintf(&b, "```markdown\n> %s\n", quote)
	if prURL != "" {
		fmt.Fprintf(&b, ">\n> _(source: %s — style only)_\n", prURL)
	}
	fmt.Fprintf(&b, "```\n\n")
	fmt.Fprintf(&b, "**Do not:**\n")
	fmt.Fprintf(&b, "- Put this quote in `src/` as a constant finding title/summary\n")
	fmt.Fprintf(&b, "- Bank synthetic train draft titles or package-generated issue text\n")
	fmt.Fprintf(&b, "- Replace core voice rules with a dump of every comment\n")
	fmt.Fprintf(&b, "- Add more than ~one short excerpt per train item (keep `%s` small)\n\n", VoiceBankFile)
	fmt.Fprintf(&b, "The CLI loads `%s` as the full rewrite prompt on GitHub comment enhance, ", VoiceBankFile)
	fmt.Fprintf(&b, "so examples in that file are what preserve wording spirit across runs.\n")
	return b.String()
}

// RelDraftPath prefers a package-relative path for display in issues.
func RelDraftPath(packagePath, draftPath string) string {
	if packagePath == "" || draftPath == "" {
		return draftPath
	}
	rel, err := filepath.Rel(packagePath, draftPath)
	if err != nil || strings.HasPrefix(rel, "..") {
		// Fall back to docs/train-drafts/<base>
		return filepath.ToSlash(filepath.Join("docs", "train-drafts", filepath.Base(draftPath)))
	}
	return filepath.ToSlash(rel)
}
