package catalogapply

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/adversarylabs/adversary/internal/train/results"
	"github.com/adversarylabs/adversary/internal/train/workspace"
)

func TestApplyExistingAdversaryWritesRuleOnce(t *testing.T) {
	root, state := t.TempDir(), t.TempDir()
	dir := filepath.Join(root, "adversaries", "operability")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	policy := filepath.Join(dir, "README.md")
	if err := os.WriteFile(policy, []byte("# Operability\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	saveResult(t, state, results.Result{ID: "candidate-1", Package: "operability", ProposedRule: "Log tenant-scoped failures.", CommentURL: "https://github.com/acme/api/pull/1#discussion_r2"})
	cfg := workspace.Config{Adversaries: workspace.AdversariesConfig{Root: "./adversaries"}}
	if err := Apply(context.Background(), state, root, cfg, "candidate-1"); err != nil {
		t.Fatal(err)
	}
	if err := Apply(context.Background(), state, root, cfg, "candidate-1"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(policy)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(raw), "Log tenant-scoped failures.") != 1 || !strings.Contains(string(raw), "adversary-catalog-train:candidate-1") {
		t.Fatalf("policy:\n%s", raw)
	}
	row, err := results.Get(state, "candidate-1")
	if err != nil || row.Status != results.StatusApplied || row.AppliedPath != policy {
		t.Fatalf("row=%+v err=%v", row, err)
	}
}

func TestApplyNewAdversaryCreatesPolicyAndManifestEntry(t *testing.T) {
	root, state := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "adversaries"), 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := "apiVersion: adversarylabs.dev/v1alpha1\nkind: AdversaryCatalog\nspec:\n  adversaries: []\n"
	if err := os.WriteFile(filepath.Join(root, "adversarylabs.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	saveResult(t, state, results.Result{
		ID: "candidate-2", Package: "release-contracts", ProposedRule: "Keep release channels synchronized.",
		AdversaryMission: "Protect private release channel contracts.",
	})
	cfg := workspace.Config{Adversaries: workspace.AdversariesConfig{Root: "./adversaries"}}
	if err := Apply(context.Background(), state, root, cfg, "candidate-2"); err != nil {
		t.Fatal(err)
	}
	policy, err := os.ReadFile(filepath.Join(root, "adversaries", "release-contracts", "README.md"))
	if err != nil || !strings.Contains(string(policy), "Keep release channels synchronized.") {
		t.Fatalf("policy=%q err=%v", policy, err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "adversarylabs.yaml"))
	if err != nil || !strings.Contains(string(raw), "id: release-contracts") || !strings.Contains(string(raw), "Protect private release channel contracts.") {
		t.Fatalf("manifest=%q err=%v", raw, err)
	}
}

func saveResult(t *testing.T, state string, row results.Result) {
	t.Helper()
	row.Kind = results.KindHuman
	row.Status = results.StatusNew
	row.Summary = "Human review evidence"
	row.CreatedAt = time.Now().UTC()
	if err := results.SaveResult(state, row); err != nil {
		t.Fatal(err)
	}
}
