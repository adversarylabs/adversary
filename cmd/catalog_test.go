package cmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/internal/train/results"
	"github.com/adversarylabs/adversary/pkg/repository"
)

type catalogReviewRuntimeStub struct {
	application.Runtime
	options application.CatalogReviewOptions
}

func (s *catalogReviewRuntimeStub) ReviewCatalog(_ context.Context, options application.CatalogReviewOptions) error {
	s.options = options
	return nil
}

func TestCatalogInitUsesProjectPort(t *testing.T) {
	var stdout, stderr bytes.Buffer
	base := lifecycleTestApp(t, repository.Repository{Root: t.TempDir()}, &stdout, &stderr).Dependencies()
	projects := &recordingProjects{}
	base.Projects = projects
	app, err := application.New(base)
	if err != nil {
		t.Fatal(err)
	}
	root := NewRootCommandWithApp(app)
	root.SetArgs([]string{"catalog", "init", filepath.Join("somewhere", "catalog")})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
}

func TestCatalogHelpDescribesLocalGeneration(t *testing.T) {
	var output bytes.Buffer
	root := NewRootCommand(&output, &bytes.Buffer{})
	root.SetArgs([]string{"catalog", "init", "--help"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"without connecting to GitHub", "editable starter"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("help=%q missing %q", output.String(), want)
		}
	}
}

func TestCatalogTrainHelpDescribesNonInteractiveLocalInbox(t *testing.T) {
	var output bytes.Buffer
	root := NewRootCommand(&output, &bytes.Buffer{})
	root.SetArgs([]string{"catalog", "train", "--help"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"exit without prompting", "never uploads training evidence to Adversary Labs", "bounded review evidence", "--author", "--exclude-author", "--model-provider", "cloudflare", "catalog train review", "reset"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("help=%q missing %q", output.String(), want)
		}
	}
}

func TestTopLevelTrainCommandIsNotExposed(t *testing.T) {
	root := NewRootCommand(&bytes.Buffer{}, &bytes.Buffer{})
	for _, command := range root.Commands() {
		if command.Name() == "train" {
			t.Fatal("top-level train command must not be exposed; use catalog train")
		}
	}
}

func TestCatalogTrainReviewAndAcceptUseLocalResultsDatabase(t *testing.T) {
	catalog := t.TempDir()
	config := `version: 1
adversaries:
  root: ./adversaries
sources:
  repos: [acme/api]
state_dir: .adversary-train
`
	if err := os.WriteFile(filepath.Join(catalog, "adversary.train.yaml"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	adversaryDir := filepath.Join(catalog, "adversaries", "operability")
	if err := os.MkdirAll(adversaryDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(adversaryDir, "README.md"), []byte("# Operability\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(catalog, ".adversary-train")
	if err := results.SaveResult(state, results.Result{
		ID: "candidate-1", Package: "data-integrity", Kind: results.KindHuman,
		Status: results.StatusNew, Summary: "Use the ledger transaction boundary", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	root := NewRootCommand(&output, &bytes.Buffer{})
	root.SetArgs([]string{"catalog", "train", "review", "--path", catalog})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"candidate", "data-integrity", "catalog train accept", "local SQLite"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("review=%q missing %q", output.String(), want)
		}
	}

	root = NewRootCommand(&bytes.Buffer{}, &bytes.Buffer{})
	root.SetArgs([]string{"catalog", "train", "accept", "candidate-1", "--path", catalog})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	result, err := results.Get(state, "candidate-1")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != results.StatusAccepted {
		t.Fatalf("status=%q", result.Status)
	}
}

func TestCatalogTrainInspectAllWalksAndCheckpointsCandidates(t *testing.T) {
	catalog := t.TempDir()
	config := `version: 1
adversaries:
  root: ./adversaries
sources:
  repos: [acme/api]
state_dir: .adversary-train
`
	if err := os.WriteFile(filepath.Join(catalog, "adversary.train.yaml"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	adversaryDir := filepath.Join(catalog, "adversaries", "operability")
	if err := os.MkdirAll(adversaryDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(adversaryDir, "README.md"), []byte("# Operability\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(catalog, ".adversary-train")
	for i, id := range []string{"candidate-1", "candidate-2", "candidate-3"} {
		if err := results.SaveResult(state, results.Result{
			ID: id, Package: "operability", Kind: results.KindHuman, Status: results.StatusNew,
			Summary: "Private operational convention " + id, CreatedAt: time.Unix(int64(i+1), 0),
		}); err != nil {
			t.Fatal(err)
		}
	}

	var stdout, stderr bytes.Buffer
	base := lifecycleTestApp(t, repository.Repository{Root: t.TempDir()}, &stdout, &stderr).Dependencies()
	base.Stdin = strings.NewReader("a\nd\ns\n")
	base.TTY = trainingNoticeTTY{}
	app, err := application.New(base)
	if err != nil {
		t.Fatal(err)
	}
	root := NewRootCommandWithApp(app)
	root.SetArgs([]string{"catalog", "train", "inspect", "--all", "--path", catalog})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Candidate 1 of 3", "[a]ccept", "accepted", "dismissed", "skipped", "Review complete: 1 accepted, 1 dismissed, 1 skipped"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("walk output=%q missing %q", stdout.String(), want)
		}
	}
	counts := map[string]int{}
	for _, id := range []string{"candidate-1", "candidate-2", "candidate-3"} {
		row, err := results.Get(state, id)
		if err != nil {
			t.Fatal(err)
		}
		counts[row.Status]++
	}
	if counts[results.StatusAccepted] != 1 || counts[results.StatusDismissed] != 1 || counts[results.StatusNew] != 1 {
		t.Fatalf("status counts=%v", counts)
	}
}

func TestCatalogTrainInspectDefaultsToBrowserReviewRuntime(t *testing.T) {
	catalog := t.TempDir()
	config := "version: 1\nadversaries:\n  root: ./adversaries\nsources:\n  repos: [acme/api]\nstate_dir: .adversary-train\n"
	if err := os.WriteFile(filepath.Join(catalog, "adversary.train.yaml"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(catalog, "adversaries", "operability")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("# Operability\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	base := lifecycleTestApp(t, repository.Repository{Root: t.TempDir()}, &stdout, &stderr).Dependencies()
	runtime := &catalogReviewRuntimeStub{Runtime: base.Runtime}
	base.Runtime = runtime
	app, err := application.New(base)
	if err != nil {
		t.Fatal(err)
	}
	root := NewRootCommandWithApp(app)
	root.SetArgs([]string{"catalog", "train", "inspect", "--path", catalog})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if runtime.options.StateRoot != filepath.Join(catalog, ".adversary-train") || len(runtime.options.Adversaries) != 1 || runtime.options.Adversaries[0] != "operability" || runtime.options.Apply == nil || runtime.options.CreatePR == nil {
		t.Fatalf("review options=%+v", runtime.options)
	}
}
