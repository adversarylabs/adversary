package cmd

import (
	"testing"

	"github.com/adversarylabs/adversary/internal/telemetry"
)

func TestSanitizeAdversarySelectionDelegates(t *testing.T) {
	got := telemetry.SanitizeAdversarySelection([]string{
		"registry.adversarylabs.ai/ci/gitlab-ci:0.0.4",
		"./x",
	})
	if len(got) != 2 || got[0] != "ci/gitlab-ci" || got[1] != "local" {
		t.Fatalf("got %#v", got)
	}
}
