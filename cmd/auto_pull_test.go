package cmd

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/pkg/adversarylabs"
	"github.com/adversarylabs/adversary/pkg/oci"
	"github.com/adversarylabs/adversary/pkg/repository"
)

func TestInventoryIdentityKey(t *testing.T) {
	cases := []struct {
		ref  string
		want string
	}{
		{"registry.example/adversarylabs/go-cli:0.0.15", "registry.example/adversarylabs/go-cli"},
		{"registry.example/adversarylabs/go-cli@sha256:abc", "registry.example/adversarylabs/go-cli"},
		{"adversarylabs/go-cli:latest", "adversarylabs/go-cli"},
		{"go-cli", "go-cli"},
		{"  Go-CLI  ", "go-cli"},
		// host:port must not be treated as a tag
		{"localhost:5000/adversarylabs/go-cli:1.0", "localhost:5000/adversarylabs/go-cli"},
	}
	for _, tc := range cases {
		if got := inventoryIdentityKey(tc.ref); got != tc.want {
			t.Errorf("inventoryIdentityKey(%q) = %q, want %q", tc.ref, got, tc.want)
		}
	}
}

func TestEnsureAccessibleAdversariesRemoteUnavailableWarns(t *testing.T) {
	var stderr bytes.Buffer
	app := lifecycleTestApp(t, repository.Repository{Root: t.TempDir()}, &bytes.Buffer{}, &stderr)
	// Point API at a closed server so Search fails.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	url := server.URL
	server.Close()

	if err := ensureAccessibleAdversaries(context.Background(), app, url, "default", &stderr); err != nil {
		t.Fatalf("expected soft failure, got %v", err)
	}
	if !strings.Contains(stderr.String(), "could not list remote adversaries") {
		t.Fatalf("expected warning, got %q", stderr.String())
	}
}

func TestEnsureAccessibleAdversariesDedupesAndAttemptsPulls(t *testing.T) {
	searchHits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/search" {
			searchHits++
			w.Header().Set("Content-Type", "application/json")
			// Two versions of the same repo plus a second identity.
			_, _ = w.Write([]byte(`{"results":[
				{"name":"go-cli","version":"0.0.15","reference":"registry.example/adversarylabs/go-cli:0.0.15"},
				{"name":"go-cli","version":"0.0.14","reference":"registry.example/adversarylabs/go-cli:0.0.14"},
				{"name":"dockerfile","version":"0.0.8","reference":"registry.example/adversarylabs/dockerfile:0.0.8"}
			]}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	var stdout, stderr bytes.Buffer
	base := lifecycleTestApp(t, repository.Repository{Root: t.TempDir()}, &stdout, &stderr).Dependencies()
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

	if err := ensureAccessibleAdversaries(context.Background(), app, server.URL, "work", &stderr); err != nil {
		t.Fatal(err)
	}
	if searchHits != 1 {
		t.Fatalf("search hits = %d", searchHits)
	}
	// Pulls will fail (no real registry), but we should attempt two identities after dedupe.
	out := stderr.String()
	if !strings.Contains(out, "Ensuring 2 accessible adversaries") {
		t.Fatalf("expected deduped target count, got %q", out)
	}
	if !strings.Contains(out, "2 pull failures") {
		t.Fatalf("expected pull failure summary, got %q", out)
	}
}

func TestAutoCommandNoPullSkipsRemoteEnsure(t *testing.T) {
	var stdout, stderr bytes.Buffer
	base := lifecycleTestApp(t, repository.Repository{Root: t.TempDir()}, &stdout, &stderr)
	deps := base.Dependencies()
	stub := &autoStubRuntime{inner: deps.Runtime}
	deps.Runtime = stub
	app, err := application.New(deps)
	if err != nil {
		t.Fatal(err)
	}
	cmd := NewRootCommandWithApp(app)
	cmd.SetArgs([]string{"auto", "--dry-run", "--no-pull"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stderr.String(), "Ensuring") || strings.Contains(stderr.String(), "could not list remote") {
		t.Fatalf("expected no remote ensure with --no-pull, stderr=%q", stderr.String())
	}
}
