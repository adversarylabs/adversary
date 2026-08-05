package githubreview

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/adversarylabs/adversary/pkg/review"
)

//go:embed default.md
var DefaultVoicePrompt string

const maxVoiceBytes = 32 << 10

// ResolveVoice loads VOICE.md from repo root if present, else embedded default.
func ResolveVoice(repoRoot string) (prompt string, info VoiceInfo) {
	info = VoiceInfo{Source: "cli_default"}
	prompt = DefaultVoicePrompt
	if strings.TrimSpace(repoRoot) == "" {
		return prompt, info
	}
	p := filepath.Join(repoRoot, "VOICE.md")
	raw, err := os.ReadFile(p)
	if err != nil {
		return prompt, info
	}
	if len(raw) == 0 {
		return prompt, info
	}
	if len(raw) > maxVoiceBytes {
		// Fall through to default.
		return prompt, info
	}
	if !utf8.Valid(raw) {
		return prompt, info
	}
	return string(raw), VoiceInfo{Source: "repo", Path: "VOICE.md"}
}

// TemplateBody builds a deterministic offline comment body.
func TemplateBody(adversary string, f review.Finding, pathStr string, line *int) string {
	var b strings.Builder
	title := strings.TrimSpace(f.Title)
	if adversary != "" {
		fmt.Fprintf(&b, "### [%s] %s — %s\n\n", f.Severity, adversary, title)
	} else {
		fmt.Fprintf(&b, "### %s — %s\n\n", f.Severity, title)
	}
	if s := strings.TrimSpace(f.Summary); s != "" {
		b.WriteString(s)
		b.WriteString("\n\n")
	}
	if pathStr != "" {
		if line != nil {
			fmt.Fprintf(&b, "**Where:** `%s:%d`\n\n", pathStr, *line)
		} else {
			fmt.Fprintf(&b, "**Where:** `%s`\n\n", pathStr)
		}
	}
	if r := strings.TrimSpace(f.Recommendation); r != "" {
		fmt.Fprintf(&b, "**Recommendation:** %s\n\n", r)
	}
	b.WriteString(Marker(adversary, f.ID, pathStr, line))
	b.WriteByte('\n')
	return b.String()
}

// EnsureMarker appends marker if missing.
func EnsureMarker(body, adversary, findingID, pathStr string, line *int) string {
	m := Marker(adversary, findingID, pathStr, line)
	if strings.Contains(body, "adversary-review:v1") {
		return body
	}
	body = strings.TrimRight(body, "\n") + "\n\n" + m + "\n"
	return body
}
