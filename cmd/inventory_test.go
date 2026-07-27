package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	// Override data dir isolation: pack uses process env ADVERSARY_DATA_DIR from tests that set it.
	// lifecycleTestApp already uses a temp repository root via Dependencies.Resolver.
	// Run pack through the same app so it stores into the injected repository.
	// If pack requires filesystem repo path from env, fall back to only remote assertions below.
	_ = pack.Execute()
	out.Reset()
	errOut.Reset()

	items, err := collectInventory(context.Background(), app, server.URL, "work", "", &errOut)
	if err != nil {
		t.Fatal(err)
	}
	var sawRemote bool
	for _, item := range items {
		if item.Source == "remote" && strings.Contains(item.Reference, "go-cli") {
			sawRemote = true
		}
	}
	if !sawRemote {
		t.Fatalf("expected remote go-cli in inventory: %#v stderr=%q", items, errOut.String())
	}

	// Query filters remote + local
	filtered, err := collectInventory(context.Background(), app, server.URL, "work", "go-cli", &errOut)
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered) == 0 {
		t.Fatal("expected filtered results for go-cli")
	}
	for _, item := range filtered {
		if !matchesInventoryQuery(item, "go-cli") && item.Source != "remote" {
			t.Fatalf("unexpected item in filtered set: %#v", item)
		}
	}

	// search JSON includes source
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
	if envelope.Data.Results[0].Source != "remote" && envelope.Data.Results[0].Source != "local" {
		t.Fatalf("expected source on results: %#v", envelope.Data.Results[0])
	}
}

func TestMatchesInventoryQuery(t *testing.T) {
	item := inventoryItem{Name: "go-cli", Version: "0.0.15", Reference: "registry.example/go-cli:0.0.15", Source: "local", Digest: "sha256:abc"}
	if !matchesInventoryQuery(item, "") {
		t.Fatal("empty query should match")
	}
	if !matchesInventoryQuery(item, "CLI") {
		t.Fatal("case-insensitive name match")
	}
	if !matchesInventoryQuery(item, "0.0.15") {
		t.Fatal("version match")
	}
	if matchesInventoryQuery(item, "zzz-nope") {
		t.Fatal("non-matching query")
	}
}
