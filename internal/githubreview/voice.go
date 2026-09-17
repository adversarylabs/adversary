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

// Voice relative paths, first hit wins within a root.
// Prefer agent/ (package agent identity), then train/, then lowercase root, then legacy VOICE.md.
var voiceRelPaths = []string{
	filepath.Join("agent", "voice.md"),
	filepath.Join("train", "voice.md"),
	"voice.md",
	"VOICE.md", // legacy
}

// LocalPackageRoots returns absolute paths for args that look like local
// adversary package directories (adversary.yaml or agent/scope.md / docs/scope.md).
func LocalPackageRoots(args []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, a := range args {
		a = strings.TrimSpace(a)
		if a == "" || strings.HasPrefix(a, "-") {
			continue
		}
		st, err := os.Stat(a)
		if err != nil || !st.IsDir() {
			continue
		}
		abs, err := filepath.Abs(a)
		if err != nil || seen[abs] {
			continue
		}
		if _, err := os.Stat(filepath.Join(abs, "adversary.yaml")); err != nil {
			if _, err2 := os.Stat(filepath.Join(abs, "agent", "scope.md")); err2 != nil {
				if _, err3 := os.Stat(filepath.Join(abs, "docs", "scope.md")); err3 != nil {
					continue
				}
			}
		}
		seen[abs] = true
		out = append(out, abs)
	}
	return out
}

// ResolveVoice loads a voice prompt from the first existing candidate under roots
// (package dirs first, then review target). Falls back to the CLI-embedded default.
func ResolveVoice(roots ...string) (prompt string, info VoiceInfo) {
	info = VoiceInfo{Source: "cli_default", ExampleBank: HasVoiceExampleBank(DefaultVoicePrompt)}
	prompt = DefaultVoicePrompt
	for _, root := range roots {
		root = strings.TrimSpace(root)
		if root == "" {
			continue
		}
		abs, err := filepath.Abs(root)
		if err != nil {
			continue
		}
		for _, rel := range voiceRelPaths {
			p := filepath.Join(abs, rel)
			raw, err := os.ReadFile(p)
			if err != nil || len(raw) == 0 {
				continue
			}
			if len(raw) > maxVoiceBytes || !utf8.Valid(raw) {
				continue
			}
			text := string(raw)
			return text, VoiceInfo{
				Source:      "package",
				Path:        rel,
				ExampleBank: HasVoiceExampleBank(text),
			}
		}
	}
	return prompt, info
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

// EnsurePlannedMarker replaces any legacy marker with the provenance-rich v2
// marker for a projected finding.
func EnsurePlannedMarker(body string, comment PlannedComment) string {
	body = stripReviewMarker(body)
	return strings.TrimRight(body, "\n") + "\n\n" + MarkerV2(comment) + "\n"
}

func stripReviewMarker(body string) string {
	for {
		start := strings.Index(body, "<!-- adversary-review:v")
		if start < 0 {
			return body
		}
		endRel := strings.Index(body[start:], "-->")
		if endRel < 0 {
			return body[:start]
		}
		body = body[:start] + body[start+endRel+3:]
	}
}
