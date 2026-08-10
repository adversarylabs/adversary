package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/adversarylabs/adversary/internal/train/results"
	"github.com/adversarylabs/adversary/internal/train/workspace"
)

func writeTrainApplyPackage(t *testing.T, root, dirName, manifestName string) string {
	t.Helper()
	dir := filepath.Join(root, dirName)
	if err := os.MkdirAll(filepath.Join(dir, "agent"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "agent", "scope.md"), []byte("# Scope\n\nReview test changes.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "adversary.yaml"), []byte("name: "+manifestName+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestResolvePackagePathRejectsMismatchedSinglePackage(t *testing.T) {
	root := t.TempDir()
	nits := writeTrainApplyPackage(t, root, "nits-adversary", "review/nits")
	cfg := workspace.Config{Adversaries: workspace.AdversariesConfig{Path: nits}}

	_, err := resolvePackagePath(root, cfg, "engineering-review")
	if err == nil {
		t.Fatal("expected package identity mismatch")
	}
	if !strings.Contains(err.Error(), `result package "engineering-review" does not match configured package "nits"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTrainResultsApplyDoesNotWriteMismatchedPackage(t *testing.T) {
	root := t.TempDir()
	nits := writeTrainApplyPackage(t, root, "nits-adversary", "review/nits")
	config := "version: 1\nadversaries:\n  path: ./nits-adversary\nsources:\n  repos:\n    - public/example\n"
	if err := os.WriteFile(filepath.Join(root, workspace.DefaultConfigName), []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(root, workspace.DefaultStateDir)
	if err := results.SaveResult(state, results.Result{
		ID:        "wrongpkg",
		RunID:     "run-1",
		Package:   "engineering-review",
		Kind:      results.KindDraft,
		Status:    results.StatusNew,
		Title:     "Test mismatch",
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	command := newTrainResultsApplyCommand(nil)
	command.SetArgs([]string{"wrongpkg", "--path", root, "--no-git", "--no-issue"})
	if err := command.Execute(); err == nil {
		t.Fatal("expected apply to reject mismatched result package")
	}
	draft := filepath.Join(nits, "docs", "train-drafts", "wrongpkg.md")
	if _, err := os.Stat(draft); !os.IsNotExist(err) {
		t.Fatalf("mismatched apply wrote draft %s: %v", draft, err)
	}
}

func TestResolvePackagePathAcceptsMatchingPackageIdentity(t *testing.T) {
	root := t.TempDir()
	nits := writeTrainApplyPackage(t, root, "nits-adversary", "review/nits")
	cfg := workspace.Config{Adversaries: workspace.AdversariesConfig{Path: nits}}

	got, err := resolvePackagePath(root, cfg, "nits")
	if err != nil {
		t.Fatal(err)
	}
	if got != nits {
		t.Fatalf("resolved %q, want %q", got, nits)
	}
}
