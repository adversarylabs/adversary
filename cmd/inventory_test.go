package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/pkg/adversarylabs"
	"github.com/adversarylabs/adversary/pkg/oci"
	"github.com/adversarylabs/adversary/pkg/repository"
)

func TestListAndSearchShareLocalAndRemoteInventory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/search" {
			http.NotFound(w, r)
			return
		}
		// Empty q and any q both return the catalog entry for this test.
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[{"name":"go-cli","version":"0.0.15","description":"CLI review","reference":"registry.example/adversarylabs/go-cli:0.0.15"}]}`))
	}))
	defer server.Close()

	repoRoot := t.TempDir()
	repo := repository.Repository{Root: repoRoot}
	var out, errOut bytes.Buffer
	base := lifecycleTestApp(t, repo, &out, &errOut).Dependencies()
	store := base.Auth.(processAuthStore).ConfigStore
	if err := store.SetAuth(adversarylabs.AuthKey(server.URL, "work"), adversarylabs.Auth{Token: "token"}); err != nil {
		t.Fatal(err)
	}
	base.API = processAPIFactory{store: store, http: server.Client()}
	base.Registries = processRegistryFactory{store: store, docker: oci.DockerCredentialStore{HomeDir: t.TempDir()}, host: base.RegistryHost, identity: store.Path}
	app, err := application.New(base)
	if err != nil {
		t.Fatal(err)
	}

	// Pack a local adversary so list/search include a local row.
	project := t.TempDir()
	writeProject(t, project)
	pack := NewRootCommandWithApp(app)
	pack.SetArgs([]string{"pack", project, "--name", "local-reviewer"})
	_ = pack.Execute()
	out.Reset()
	errOut.Reset()

	items, err := collectInventory(context.Background(), app, server.URL, "work", "", &errOut, inventoryScope{})
	if err != nil {
		t.Fatal(err)
	}
	var sawCatalog bool
	for _, item := range items {
		if item.Status == inventoryStatusCatalog && strings.Contains(item.Reference, "go-cli") {
			sawCatalog = true
		}
	}
	if !sawCatalog {
		t.Fatalf("expected catalog go-cli in inventory: %#v stderr=%q", items, errOut.String())
	}

	// Query filters remote + local
	filtered, err := collectInventory(context.Background(), app, server.URL, "work", "go-cli", &errOut, inventoryScope{})
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered) == 0 {
		t.Fatal("expected filtered results for go-cli")
	}
	for _, item := range filtered {
		if !matchesInventoryQuery(item, "go-cli") && item.Status != inventoryStatusCatalog {
			t.Fatalf("unexpected item in filtered set: %#v", item)
		}
	}

	// search JSON includes status
	out.Reset()
	errOut.Reset()
	cmd := NewRootCommandWithApp(app)
	cmd.SetArgs([]string{"--api-url", server.URL, "--profile", "work", "search", "--format", "json"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Data searchDTO `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &envelope); err != nil {
		t.Fatalf("json: %v out=%s", err, out.String())
	}
	if len(envelope.Data.Results) == 0 {
		t.Fatalf("expected results, got %s", out.String())
	}
	st := envelope.Data.Results[0].Status
	if st != inventoryStatusCatalog && st != inventoryStatusInstalled && st != inventoryStatusOutdated {
		t.Fatalf("expected status on results: %#v", envelope.Data.Results[0])
	}
}

func TestMatchesInventoryQuery(t *testing.T) {
	item := inventoryItem{
		Name: "go-cli", Version: "0.0.15", Reference: "registry.example/go-cli:0.0.15",
		Source: inventoryOriginLocal, Status: inventoryStatusInstalled, Digest: "sha256:abc",
	}
	if !matchesInventoryQuery(item, "") {
		t.Fatal("empty query should match")
	}
	if !matchesInventoryQuery(item, "CLI") {
		t.Fatal("case-insensitive name match")
	}
	if !matchesInventoryQuery(item, "0.0.15") {
		t.Fatal("version match")
	}
	if !matchesInventoryQuery(item, "installed") {
		t.Fatal("status match")
	}
	if matchesInventoryQuery(item, "zzz-nope") {
		t.Fatal("non-matching query")
	}
}

func TestIsRetiredPublisherInventory(t *testing.T) {
	cases := []struct {
		item inventoryItem
		want bool
	}{
		{
			item: inventoryItem{
				Name:      "go-cli",
				Reference: "registry.adversarylabs.ai/adversarylabs/go-cli:0.0.16",
			},
			want: true,
		},
		{
			item: inventoryItem{
				Name:      "go-cli",
				Reference: "registry.adversarylabs.ai/library/go-cli:0.0.16",
			},
			want: true,
		},
		{
			item: inventoryItem{
				Name:      "adversarylabs/dockerfile",
				Reference: "registry.adversarylabs.ai/adversarylabs/dockerfile:0.0.9",
			},
			want: true,
		},
		{
			item: inventoryItem{
				Name:      "go/cli",
				Reference: "registry.adversarylabs.ai/go/cli",
			},
			want: false,
		},
		{
			item: inventoryItem{
				Name:      "security/secrets",
				Reference: "registry.adversarylabs.ai/security/secrets:0.0.9",
			},
			want: false,
		},
		{
			item: inventoryItem{
				Name:      "adversary",
				Reference: "localhost:8787/adversarylabs/adversary:0.1.0",
			},
			want: false, // local registry packs stay visible
		},
		{
			item: inventoryItem{
				Name:      "adversary",
				Reference: "localhost:8787/marc/adversary:0.1.0",
			},
			want: false,
		},
		{
			item: inventoryItem{Name: "adversarylabs/legacy"},
			want: true,
		},
	}
	for _, tc := range cases {
		if got := isRetiredPublisherInventory(tc.item); got != tc.want {
			t.Fatalf("isRetiredPublisherInventory(%#v) = %v, want %v", tc.item, got, tc.want)
		}
	}
}

func TestMergeInventoryByNameStatuses(t *testing.T) {
	items := []inventoryItem{
		{Name: "go-cli", Version: "0.0.6", Source: inventoryOriginLocal, Reference: "reg/go/cli:0.0.6"},
		{Name: "go-cli", Version: "0.0.16", Source: inventoryOriginLocal, Reference: "reg/go/cli:0.0.16"},
		{Name: "go-cli", Version: "0.0.15", Source: inventoryOriginLocal, Reference: "reg/go/cli:0.0.15"},
		// local behind catalog → outdated
		{Name: "dockerfile", Version: "0.0.9", Source: inventoryOriginLocal, Reference: "localhost:8787/marc/dockerfile:0.0.9"},
		{Name: "dockerfile", Version: "0.0.10", Source: inventoryOriginRemote, Reference: "reg/container/dockerfile"},
		// same version: installed (not catalog-only)
		{Name: "secrets", Version: "0.0.9", Source: inventoryOriginLocal, Reference: "reg/library/secrets:0.0.9"},
		{Name: "secrets", Version: "0.0.9", Source: inventoryOriginRemote, Reference: "reg/security/secrets"},
		// catalog only
		{Name: "go/cli", Version: "0.0.17", Source: inventoryOriginRemote, Reference: "reg/go/cli"},
		// local only
		{Name: "local/tool", Version: "1.0.0", Source: inventoryOriginLocal, Reference: "localhost:8787/marc/tool:1.0.0"},
		// local ahead of catalog → installed
		{Name: "ahead", Version: "2.0.0", Source: inventoryOriginLocal, Reference: "localhost/ahead:2.0.0"},
		{Name: "ahead", Version: "1.0.0", Source: inventoryOriginRemote, Reference: "reg/ahead"},
	}

	got := mergeInventoryByName(items)
	if len(got) != 6 {
		t.Fatalf("expected 6 names, got %d: %#v", len(got), got)
	}

	byName := map[string]inventoryItem{}
	for _, item := range got {
		byName[item.Name] = item
	}
	if byName["go-cli"].Version != "0.0.16" || byName["go-cli"].Status != inventoryStatusInstalled {
		t.Fatalf("go-cli want installed 0.0.16, got %#v", byName["go-cli"])
	}
	if byName["dockerfile"].Status != inventoryStatusOutdated || byName["dockerfile"].Version != "0.0.9" || byName["dockerfile"].LatestVersion != "0.0.10" {
		t.Fatalf("dockerfile want outdated 0.0.9→0.0.10, got %#v", byName["dockerfile"])
	}
	if byName["secrets"].Status != inventoryStatusInstalled {
		t.Fatalf("secrets same version should be installed, got %#v", byName["secrets"])
	}
	if byName["go/cli"].Status != inventoryStatusCatalog {
		t.Fatalf("go/cli want catalog: %#v", byName["go/cli"])
	}
	if byName["local/tool"].Status != inventoryStatusInstalled {
		t.Fatalf("local/tool want installed: %#v", byName["local/tool"])
	}
	if byName["ahead"].Status != inventoryStatusInstalled || byName["ahead"].Version != "2.0.0" {
		t.Fatalf("ahead local newer should be installed: %#v", byName["ahead"])
	}
}

func TestCollectInventoryQueryMatchesStatusAfterMerge(t *testing.T) {
	// Local is behind catalog. A query of "outdated" or the catalog version must
	// still find the row after status/latestVersion are computed (not pre-merge).
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/search" {
			http.NotFound(w, r)
			return
		}
		// Full catalog when q is empty (client-side filter after merge).
		if r.URL.Query().Get("q") != "" {
			t.Errorf("expected empty remote search q for post-merge filtering, got %q", r.URL.Query().Get("q"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[{"name":"pkg/behind","version":"0.0.2","description":"catalog","reference":"registry.example/pkg/behind:0.0.2"}]}`))
	}))
	defer server.Close()

	repo := repository.Repository{Root: t.TempDir()}
	var out, errOut bytes.Buffer
	base := lifecycleTestApp(t, repo, &out, &errOut).Dependencies()
	store := base.Auth.(processAuthStore).ConfigStore
	if err := store.SetAuth(adversarylabs.AuthKey(server.URL, "default"), adversarylabs.Auth{Token: "token"}); err != nil {
		t.Fatal(err)
	}
	base.API = processAPIFactory{store: store, http: server.Client()}
	base.Registries = processRegistryFactory{store: store, docker: oci.DockerCredentialStore{HomeDir: t.TempDir()}, host: base.RegistryHost, identity: store.Path}
	app, err := application.New(base)
	if err != nil {
		t.Fatal(err)
	}

	project := t.TempDir()
	writeProject(t, project)
	if err := os.WriteFile(filepath.Join(project, "adversary.yaml"), []byte(`name: pkg/behind
version: 0.0.1
description: local install only phrase
runtime:
  name: node
  version: "22"
  command:
    - dist/index.js
`), 0o644); err != nil {
		t.Fatal(err)
	}
	pack := NewRootCommandWithApp(app)
	pack.SetArgs([]string{"pack", project})
	if err := pack.Execute(); err != nil {
		t.Fatalf("pack: %v", err)
	}

	for _, q := range []string{"outdated", "0.0.2"} {
		errOut.Reset()
		items, err := collectInventory(context.Background(), app, server.URL, "default", q, &errOut, inventoryScope{})
		if err != nil {
			t.Fatal(err)
		}
		if len(items) != 1 || items[0].Name != "pkg/behind" || items[0].Status != inventoryStatusOutdated {
			t.Fatalf("query %q: want one outdated pkg/behind, got %#v stderr=%q", q, items, errOut.String())
		}
		if items[0].Version != "0.0.1" || items[0].LatestVersion != "0.0.2" {
			t.Fatalf("query %q: versions %#v", q, items[0])
		}
	}
}

func TestInventoryScopeFilters(t *testing.T) {
	items := []inventoryItem{
		{Name: "a", Status: inventoryStatusInstalled},
		{Name: "b", Status: inventoryStatusCatalog},
		{Name: "c", Status: inventoryStatusOutdated},
	}
	filter := func(scope inventoryScope) []string {
		var names []string
		for _, item := range items {
			if scope.allows(item.Status) {
				names = append(names, item.Name)
			}
		}
		return names
	}
	if got := filter(inventoryScope{}); strings.Join(got, ",") != "a,b,c" {
		t.Fatalf("all: %v", got)
	}
	if got := filter(inventoryScope{Installed: true}); strings.Join(got, ",") != "a,c" {
		t.Fatalf("installed includes outdated: %v", got)
	}
	if got := filter(inventoryScope{Catalog: true}); strings.Join(got, ",") != "b" {
		t.Fatalf("catalog: %v", got)
	}
	if got := filter(inventoryScope{Outdated: true}); strings.Join(got, ",") != "c" {
		t.Fatalf("outdated: %v", got)
	}
	if err := (inventoryScope{Installed: true, Catalog: true}).validate(); err == nil {
		t.Fatal("expected mutual exclusion error")
	}
}

func TestLocalInventoryMatchesManifestDescription(t *testing.T) {
	// Offline remote: force search API failure so only local inventory is considered.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	repo := repository.Repository{Root: t.TempDir()}
	var out, errOut bytes.Buffer
	base := lifecycleTestApp(t, repo, &out, &errOut).Dependencies()
	base.API = processAPIFactory{store: base.Auth.(processAuthStore).ConfigStore, http: server.Client()}
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

	project := t.TempDir()
	writeProject(t, project)
	// Unique phrase only present in description, not name/version.
	const phrase = "xylophone-lifecycle-boundary"
	manifestPath := filepath.Join(project, "adversary.yaml")
	// writeProject already created adversary.yaml; rewrite with description.
	data := []byte(`name: local/security-reviewer
version: 1.4.2
description: Reviews ` + phrase + ` with evidence.
runtime:
  name: node
  version: "22"
  command:
    - dist/index.js
`)
	if err := os.WriteFile(manifestPath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	out.Reset()
	errOut.Reset()
	pack := NewRootCommandWithApp(app)
	pack.SetArgs([]string{"pack", project})
	if err := pack.Execute(); err != nil {
		t.Fatalf("pack: %v stderr=%s", err, errOut.String())
	}

	errOut.Reset()
	items, err := collectInventory(context.Background(), app, server.URL, "default", phrase, &errOut, inventoryScope{})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) == 0 {
		t.Fatalf("expected local match on description phrase %q; stderr=%q", phrase, errOut.String())
	}
	var found bool
	for _, item := range items {
		if item.Status == inventoryStatusInstalled && strings.Contains(strings.ToLower(item.Description), phrase) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected installed description containing %q, got %#v", phrase, items)
	}
}

func TestOutdatedCommandListsOnlyOutdated(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/search" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[
			{"name":"pkg/old","version":"0.0.2","description":"newer","reference":"registry.example/pkg/old:0.0.2"},
			{"name":"pkg/current","version":"1.0.0","description":"same","reference":"registry.example/pkg/current:1.0.0"}
		]}`))
	}))
	defer server.Close()

	repo := repository.Repository{Root: t.TempDir()}
	var out, errOut bytes.Buffer
	base := lifecycleTestApp(t, repo, &out, &errOut).Dependencies()
	store := base.Auth.(processAuthStore).ConfigStore
	if err := store.SetAuth(adversarylabs.AuthKey(server.URL, "default"), adversarylabs.Auth{Token: "token"}); err != nil {
		t.Fatal(err)
	}
	base.API = processAPIFactory{store: store, http: server.Client()}
	base.Registries = processRegistryFactory{store: store, docker: oci.DockerCredentialStore{HomeDir: t.TempDir()}, host: base.RegistryHost, identity: store.Path}
	app, err := application.New(base)
	if err != nil {
		t.Fatal(err)
	}

	// Install older pkg/old and current pkg/current via pack (name/version in manifest).
	for _, tc := range []struct {
		name, version string
	}{
		{"pkg/old", "0.0.1"},
		{"pkg/current", "1.0.0"},
	} {
		project := t.TempDir()
		writeProject(t, project)
		manifestPath := filepath.Join(project, "adversary.yaml")
		data := []byte(`name: ` + tc.name + `
version: ` + tc.version + `
description: test package
runtime:
  name: node
  version: "22"
  command:
    - dist/index.js
`)
		if err := os.WriteFile(manifestPath, data, 0o644); err != nil {
			t.Fatal(err)
		}
		out.Reset()
		errOut.Reset()
		pack := NewRootCommandWithApp(app)
		pack.SetArgs([]string{"pack", project})
		if err := pack.Execute(); err != nil {
			t.Fatalf("pack %s: %v stderr=%s", tc.name, err, errOut.String())
		}
	}

	out.Reset()
	errOut.Reset()
	cmd := NewRootCommandWithApp(app)
	cmd.SetArgs([]string{"--api-url", server.URL, "outdated", "--format", "json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("outdated: %v stderr=%s", err, errOut.String())
	}
	var envelope struct {
		Data searchDTO `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &envelope); err != nil {
		t.Fatalf("json: %v out=%s", err, out.String())
	}
	if len(envelope.Data.Results) != 1 {
		t.Fatalf("want 1 outdated, got %#v out=%s", envelope.Data.Results, out.String())
	}
	r := envelope.Data.Results[0]
	if r.Name != "pkg/old" || r.Status != inventoryStatusOutdated || r.Version != "0.0.1" || r.LatestVersion != "0.0.2" {
		t.Fatalf("unexpected outdated row: %#v", r)
	}
}
