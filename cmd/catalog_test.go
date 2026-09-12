package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/internal/train/results"
	"github.com/adversarylabs/adversary/pkg/repository"
)

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
	for _, want := range []string{"exit without prompting", "never uploads training evidence", "--author", "--exclude-author", "catalog train review"} {
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
