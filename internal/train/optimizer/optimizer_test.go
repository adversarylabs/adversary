package optimizer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/adversarylabs/adversary/internal/train/critic"
)

func TestProposeWritesPatchAndExperiment(t *testing.T) {
	hyps := []critic.Hypothesis{
		{
			ID:                     "h-1-missed-concern",
			ObservedFailure:        "missed concerns",
			GeneralizedFailureMode: "under-detection of lifecycle issues",
			WhyNotRepoSpecific:     "pattern across cases",
			Principle:              "expand detection with evidence",
			OwningAdversary:        "engineering-review",
			SuggestedChangeSurface: "prompt",
			Counterexamples:        []string{"style-only"},
		},
	}
	dir := t.TempDir()
	prop, rec, err := Propose(hyps, "engineering-review", "0.0.11", []string{"c1", "c2"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if prop.Status != "proposed" || rec.Status != "proposed" {
		t.Fatalf("status prop=%s rec=%s", prop.Status, rec.Status)
	}
	if rec.Decision != "" {
		t.Fatal("decision must be empty")
	}
	if _, err := os.Stat(prop.PatchPath); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(prop.PatchPath)
	if len(raw) < 20 {
		t.Fatalf("patch too small")
	}
	if _, err := os.Stat(filepath.Join(dir, prop.ID+".experiment.json")); err != nil {
		t.Fatal(err)
	}
}
