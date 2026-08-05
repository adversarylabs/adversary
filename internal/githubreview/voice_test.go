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
	// Prefer agent/voice.md over legacy VOICE.md
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "agent"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "VOICE.md"), []byte("legacy VOICE"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "agent", "voice.md"), []byte("Custom voice for Acme"), 0o644); err != nil {
		t.Fatal(err)
	}
	prompt, info = ResolveVoice(dir)
	if info.Source != "package" || info.Path != filepath.Join("agent", "voice.md") || prompt != "Custom voice for Acme" {
		t.Fatalf("%#v %q", info, prompt)
	}
	// Package root wins over target root
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "voice.md"), []byte("target voice"), 0o644); err != nil {
		t.Fatal(err)
	}
	prompt, info = ResolveVoice(dir, target)
	if prompt != "Custom voice for Acme" {
		t.Fatalf("package should win: %q %#v", prompt, info)
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
