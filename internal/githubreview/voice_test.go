package githubreview

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adversarylabs/adversary/pkg/review"
)

func TestResolveVoiceDefaultAndOverride(t *testing.T) {
	prompt, info := ResolveVoice("")
	if info.Source != "cli_default" || !strings.Contains(prompt, "Adversary Labs") {
		t.Fatalf("%s %q", info.Source, prompt[:min(40, len(prompt))])
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "VOICE.md"), []byte("Custom voice for Acme"), 0o644); err != nil {
		t.Fatal(err)
	}
	prompt, info = ResolveVoice(dir)
	if info.Source != "repo" || info.Path != "VOICE.md" || prompt != "Custom voice for Acme" {
		t.Fatalf("%#v %q", info, prompt)
	}
}

func TestTemplateBodyMarker(t *testing.T) {
	line := 2
	body := TemplateBody("go-cli", review.Finding{
		ID: "id1", Title: "T", Severity: "high", Summary: "sum", Recommendation: "rec",
	}, "f.go", &line)
	if !strings.Contains(body, "adversary-review:v1") || !strings.Contains(body, "f.go:2") {
		t.Fatal(body)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
