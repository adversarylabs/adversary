package githubreview

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHasVoiceExampleBank(t *testing.T) {
	if HasVoiceExampleBank(DefaultVoicePrompt) {
		t.Fatal("CLI default should not claim train example bank")
	}
	with := DefaultVoicePrompt + "\n\n" + VoiceExampleBankHeading + "\n\n### Ship / OK\n\n> Looks fine.\n"
	if !HasVoiceExampleBank(with) {
		t.Fatal("expected example bank detection")
	}
}

func TestBuildRewritePromptIncludesBankInstructions(t *testing.T) {
	voice := "# Review voice\n\nBe blunt.\n\n" + VoiceExampleBankHeading + "\n\n### Ship / OK\n\n> Looks all reasonable to me\n"
	prompt := BuildRewritePrompt(voice)
	for _, want := range []string{
		"CLI comment rewrite task",
		"few-shot style only",
		"copy any example quote",
		VoiceExampleBankHeading,
		"Looks all reasonable to me",
		"Be blunt",
	} {
		if !strings.Contains(prompt, want) {
			snip := prompt
			if len(snip) > 900 {
				snip = snip[:900]
			}
			t.Fatalf("missing %q in prompt:\n%s", want, snip)
		}
	}
}

func TestExampleBankHint(t *testing.T) {
	if got := exampleBankHint("info", "nit: rename", "bad name"); got != "Nits / style" {
		t.Fatalf("%s", got)
	}
	if got := exampleBankHint("high", "data race", "broken lock"); got != "Defects / correctness" {
		t.Fatalf("%s", got)
	}
	if got := exampleBankHint("low", "ship it", "no material issues"); got != "Ship / OK" {
		t.Fatalf("%s", got)
	}
	if got := exampleBankHint("medium", "Questionable approach", "fragile dispatch"); got != "Design / technical judgment" {
		t.Fatalf("%s", got)
	}
}

func TestResolveVoiceDetectsExampleBank(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "agent"), 0o755); err != nil {
		t.Fatal(err)
	}
	body := "# v\n\n" + VoiceExampleBankHeading + "\n\n### Ship / OK\n\n> ok\n"
	if err := os.WriteFile(filepath.Join(dir, "agent", "voice.md"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	_, info := ResolveVoice(dir)
	if !info.ExampleBank || info.Source != "package" {
		t.Fatalf("%+v", info)
	}
}
