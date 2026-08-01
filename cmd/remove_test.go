package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/pkg/oci"
	"github.com/adversarylabs/adversary/pkg/repository"
)

func TestRemoveIsCanonicalAndRmIsAlias(t *testing.T) {
	root := NewRootCommand(&bytes.Buffer{}, &bytes.Buffer{})
	remove, _, err := root.Find([]string{"remove"})
	if err != nil {
		t.Fatal(err)
	}
	rm, _, err := root.Find([]string{"rm"})
	if err != nil {
		t.Fatal(err)
	}
	if remove != rm || remove.Name() != "remove" {
		t.Fatalf("remove=%p rm=%p name=%q", remove, rm, remove.Name())
	}
}

func TestEntryMatchesRemoveSelector(t *testing.T) {
	entry := repository.Entry{
		Record:             repository.Record{Name: "go/cli", Version: "0.0.15"},
		CanonicalReference: "registry.example/go/cli:0.0.15",
		Digest:             "sha256:abc123",
	}
	cases := []struct {
		sel  string
		want bool
	}{
		{"go/cli", true},
		{"GO/CLI", true},
		{"go/cli:0.0.15", true},
		{"go/cli:0.0.16", false},
		{"registry.example/go/cli:0.0.15", true},
		{"sha256:abc123", true},
		{"abc123", true},
		{"other", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := entryMatchesRemoveSelector(entry, tc.sel); got != tc.want {
			t.Fatalf("selector %q: got %v want %v", tc.sel, got, tc.want)
		}
	}
}

func TestSelectRemoveTargetsRequiresMatch(t *testing.T) {
	entries := []repository.Entry{
		{Record: repository.Record{Name: "go/cli", Version: "0.0.1"}, Digest: "sha256:a", CanonicalReference: "r/go/cli:0.0.1"},
		{Record: repository.Record{Name: "go/cli", Version: "0.0.2"}, Digest: "sha256:b", CanonicalReference: "r/go/cli:0.0.2"},
		{Record: repository.Record{Name: "security/secrets", Version: "1.0.0"}, Digest: "sha256:c", CanonicalReference: "r/security/secrets:1.0.0"},
	}
	got, err := selectRemoveTargets(entries, []string{"go/cli"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("name should remove all versions: %#v", got)
	}
	got, err = selectRemoveTargets(entries, []string{"go/cli:0.0.1"}, true)
	if err != nil || len(got) != 1 || got[0].Digest != "sha256:a" {
		t.Fatalf("version pin: got %#v err=%v", got, err)
	}
	_, err = selectRemoveTargets(entries, []string{"missing/pkg"}, true)
	if err == nil || !application.IsKind(err, "not_found") {
		t.Fatalf("want not_found, got %v", err)
	}
	// Later passes tolerate empty matches.
	got, err = selectRemoveTargets(entries, []string{"missing/pkg"}, false)
	if err != nil || len(got) != 0 {
		t.Fatalf("requireMatch=false: got %#v err=%v", got, err)
	}
}

func TestDeleteStoredRefTreatsMissingAsSuccess(t *testing.T) {
	repo := repository.Repository{Root: t.TempDir()}
	// DeleteRef on missing ref should surface NotExist through deleteStoredRef → nil.
	// Use processRepository wrapper via lifecycle app.
	var out, errOut bytes.Buffer
	app := lifecycleTestApp(t, repo, &out, &errOut)
	err := deleteStoredRef(app.Dependencies().Repository, "registry.example/none/pkg:1.0.0", "sha256:dead")
	if err != nil {
		t.Fatalf("missing ref should be ok: %v", err)
	}
}

func TestRemoveByNameAndAll(t *testing.T) {
	repo := repository.Repository{Root: t.TempDir()}
	var out, errOut bytes.Buffer
	base := lifecycleTestApp(t, repo, &out, &errOut).Dependencies()
	base.Registries = processRegistryFactory{
		store:    base.Auth.(processAuthStore).ConfigStore,
		docker:   oci.DockerCredentialStore{HomeDir: t.TempDir()},
		host:     base.RegistryHost,
		identity: base.Auth.(processAuthStore).ConfigStore.Path,
	}
	app, err := application.New(base)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name, version string
	}{
		{"pkg/one", "1.0.0"},
		{"pkg/one", "1.0.1"},
		{"pkg/two", "2.0.0"},
	} {
		project := t.TempDir()
		writeProject(t, project)
		if err := os.WriteFile(filepath.Join(project, "adversary.yaml"), []byte(`name: `+tc.name+`
version: `+tc.version+`
description: remove test
runtime:
  name: node
  version: "22"
  command:
    - dist/index.js
`), 0o644); err != nil {
			t.Fatal(err)
		}
		out.Reset()
		errOut.Reset()
		pack := NewRootCommandWithApp(app)
		pack.SetArgs([]string{"pack", project})
		if err := pack.Execute(); err != nil {
			t.Fatalf("pack %s@%s: %v stderr=%s", tc.name, tc.version, err, errOut.String())
		}
	}

	// Dry-run by name: both versions of pkg/one
	out.Reset()
	errOut.Reset()
	cmd := NewRootCommandWithApp(app)
	cmd.SetArgs([]string{"remove", "pkg/one", "--dry-run", "--format", "json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("dry-run: %v stderr=%s", err, errOut.String())
	}
	var envelope struct {
		Data removeDTO `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &envelope); err != nil {
		t.Fatalf("json: %v out=%s", err, out.String())
	}
	if !envelope.Data.DryRun || envelope.Data.PlannedDeletions != 2 {
		t.Fatalf("dry-run dto: %#v out=%s", envelope.Data, out.String())
	}

	// Still present after dry-run
	entries, err := app.Dependencies().Resolver.Entries(100)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("dry-run must not delete, got %d entries", len(entries))
	}

	// Remove by name
	out.Reset()
	errOut.Reset()
	cmd = NewRootCommandWithApp(app)
	cmd.SetArgs([]string{"remove", "pkg/one"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("remove name: %v stderr=%s", err, errOut.String())
	}
	if !strings.Contains(out.String(), "Removed") || !strings.Contains(out.String(), "pkg/one") {
		t.Fatalf("remove output=%q", out.String())
	}
	entries, err = app.Dependencies().Resolver.Entries(100)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Record.Name != "pkg/two" {
		t.Fatalf("expected only pkg/two left, got %#v", entries)
	}

	// --all requires --yes
	out.Reset()
	errOut.Reset()
	cmd = NewRootCommandWithApp(app)
	cmd.SetArgs([]string{"remove", "--all"})
	if err := cmd.Execute(); err == nil || !application.IsKind(err, "confirmation") {
		t.Fatalf("want confirmation error, got %v", err)
	}

	// --all --yes clears store
	out.Reset()
	errOut.Reset()
	cmd = NewRootCommandWithApp(app)
	cmd.SetArgs([]string{"remove", "--all", "--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("remove --all: %v stderr=%s", err, errOut.String())
	}
	entries, err = app.Dependencies().Resolver.Entries(100)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("store should be empty, got %#v", entries)
	}
}

func TestRemoveUnknownSelectorErrors(t *testing.T) {
	repo := repository.Repository{Root: t.TempDir()}
	var out, errOut bytes.Buffer
	app := lifecycleTestApp(t, repo, &out, &errOut)
	cmd := NewRootCommandWithApp(app)
	cmd.SetArgs([]string{"remove", "does-not-exist"})
	err := cmd.Execute()
	if err == nil || !application.IsKind(err, "not_found") {
		t.Fatalf("want not_found, got %v", err)
	}
}
