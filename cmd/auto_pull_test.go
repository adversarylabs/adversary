package cmd

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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

func TestPreferCatalogVersion(t *testing.T) {
	cases := []struct {
		candidate, current string
		want               bool
	}{
		{"0.0.15", "0.0.14", true},
		{"0.0.14", "0.0.15", false},
		{"latest", "0.0.15", true},
		{"0.0.15", "latest", false},
		{"", "0.0.1", false},
		{"0.0.1", "", true},
		{"beta", "alpha", true}, // non-semver lexicographic
	}
	for _, tc := range cases {
		if got := preferCatalogVersion(tc.candidate, tc.current); got != tc.want {
			t.Errorf("preferCatalogVersion(%q, %q) = %v, want %v", tc.candidate, tc.current, got, tc.want)
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

func TestEnsureAccessibleAdversariesPropagatesCatalogCancellation(t *testing.T) {
	var stderr bytes.Buffer
	app := lifecycleTestApp(t, repository.Repository{Root: t.TempDir()}, &bytes.Buffer{}, &stderr)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := ensureAccessibleAdversaries(ctx, app, server.URL, "default", &stderr)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if strings.Contains(stderr.String(), "using local store only") {
		t.Fatalf("cancellation must not be softened: %q", stderr.String())
	}
}

func TestEnsureAccessibleAdversariesPrefersNewestVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/search" {
			w.Header().Set("Content-Type", "application/json")
			// Older version listed first — must still pull 0.0.15 after dedupe.
			_, _ = w.Write([]byte(`{"results":[
				{"name":"go-cli","version":"0.0.14","reference":"registry.example/adversarylabs/go-cli:0.0.14"},
				{"name":"go-cli","version":"0.0.15","reference":"registry.example/adversarylabs/go-cli:0.0.15"},
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
	out := stderr.String()
	if !strings.Contains(out, "Ensuring 2 accessible adversaries") {
		t.Fatalf("expected deduped target count, got %q", out)
	}
	if !strings.Contains(out, "go-cli:0.0.15") {
		t.Fatalf("expected newest go-cli reference in pull attempts, got %q", out)
	}
	if strings.Contains(out, "go-cli:0.0.14") {
		t.Fatalf("stale go-cli version should not be pulled, got %q", out)
	}
	if !strings.Contains(out, "2 pull failures") {
		t.Fatalf("expected pull failure summary, got %q", out)
	}
}

func TestEnsureAccessibleAdversariesPropagatesPullCancellation(t *testing.T) {
	// Hang registry resolve so cancel is observed on the pull path, not a fast soft-fail.
	registryHang := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer registryHang.Close()
	// httptest URL is http://127.0.0.1:port — strip scheme for OCI host:port form.
	regHost := strings.TrimPrefix(registryHang.URL, "http://")
	ref := regHost + "/adversarylabs/go-cli:0.0.15"

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/search" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"results":[
				{"name":"go-cli","version":"0.0.15","reference":"` + ref + `"}
			]}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer api.Close()

	var stdout, stderr bytes.Buffer
	base := lifecycleTestApp(t, repository.Repository{Root: t.TempDir()}, &stdout, &stderr).Dependencies()
	store := base.Auth.(processAuthStore).ConfigStore
	if err := store.SetAuth(adversarylabs.AuthKey(api.URL, "work"), adversarylabs.Auth{Token: "token"}); err != nil {
		t.Fatal(err)
	}
	base.API = processAPIFactory{store: store, http: api.Client()}
	base.Registries = processRegistryFactory{store: store, docker: oci.DockerCredentialStore{HomeDir: t.TempDir()}, host: base.RegistryHost, identity: store.Path}
	app, err := application.New(base)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- ensureAccessibleAdversaries(ctx, app, api.URL, "work", &stderr)
	}()
	// Give the pull enough time to enter the hung registry resolve, then cancel.
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err = <-errCh:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for ensureAccessibleAdversaries")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled; stderr=%q", err, stderr.String())
	}
	if strings.Contains(stderr.String(), "pull failures") {
		t.Fatalf("cancelled pull must not be counted as soft failure: %q", stderr.String())
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
