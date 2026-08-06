package githubreview

import "strings"

// VoiceExampleBankHeading is the section train apply / package voice stubs use
// for few-shot maintainer quotes. Must stay aligned with train/results voice bank.
const VoiceExampleBankHeading = "## Example maintainer comments (style only)"

// rewriteTaskPreamble is prepended to package/CLI voice markdown so models
// always treat the example bank as few-shot style, not copy-paste targets.
const rewriteTaskPreamble = `# CLI comment rewrite task

You rewrite **one** automated code-review finding into a single GitHub pull request
comment body (Markdown).

## Package voice document

Everything after the separator is the package (or CLI default) voice file—typically
` + "`agent/voice.md`" + `. Follow its core voice, length, bans, and output rules.

## Example bank (few-shot style only)

If the voice document contains a section titled:

` + "`" + VoiceExampleBankHeading + "`" + `

then treat the blockquotes under it as **style few-shots**:

1. Match cadence, bluntness, and structure from examples in the subsection that best
   fits this finding (Ship / OK, Design / technical judgment, Defects / correctness,
   Nits / style)—use severity and title/summary as hints.
2. **Do not** copy any example quote unchanged as the comment body.
3. **Do not** invent technical facts from examples that are not present in the
   finding input (title, templateBody, path, line).
4. Re-ground every claim in the finding evidence in the JSON input.
5. If the example bank is empty or missing, follow core voice only.

## JSON input fields

- findingId, adversary, severity, confidence, title
- path, line, endLine (anchor)
- templateBody (deterministic draft to rewrite)
- exampleBankHint (preferred example-bank subsection: Ship / OK, Design / technical judgment, Defects / correctness, or Nits / style)

Return only schema-valid JSON with a single "body" string (the PR comment).
`

// HasVoiceExampleBank reports whether voice markdown includes the train gold bank.
func HasVoiceExampleBank(voiceMarkdown string) bool {
	return strings.Contains(voiceMarkdown, VoiceExampleBankHeading)
}

// BuildRewritePrompt wraps package/CLI voice markdown with explicit rewrite
// instructions so agent/voice.md example banks are used when generating comments.
func BuildRewritePrompt(voiceMarkdown string) string {
	voice := strings.TrimSpace(voiceMarkdown)
	if voice == "" {
		voice = strings.TrimSpace(DefaultVoicePrompt)
	}
	var b strings.Builder
	b.WriteString(rewriteTaskPreamble)
	b.WriteString("\n---\n\n")
	b.WriteString(voice)
	if !strings.HasSuffix(voice, "\n") {
		b.WriteByte('\n')
	}
	return b.String()
}
