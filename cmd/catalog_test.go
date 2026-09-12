package cmd

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adversarylabs/adversary/internal/application"
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
