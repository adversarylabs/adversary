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

	"github.com/doomerlabs/doomer/internal/application"
	"github.com/doomerlabs/doomer/pkg/adversarylabs"
	"github.com/doomerlabs/doomer/pkg/oci"
	"github.com/doomerlabs/doomer/pkg/repository"
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
		// Concrete semver beats mutable latest so ensure can pin a published tag.
		{"latest", "0.0.15", false},
		{"0.0.15", "latest", true},
		{"", "0.0.1", false},
		{"0.0.1", "", true},
		{"beta", "alpha", true}, // non-semver lexicographic
		{"latest", "beta", true},
	}
	for _, tc := range cases {
		if got := preferCatalogVersion(tc.candidate, tc.current); got != tc.want {
			t.Errorf("preferCatalogVersion(%q, %q) = %v, want %v", tc.candidate, tc.current, got, tc.want)
		}
	}
}

func TestCatalogPullReference(t *testing.T) {
	cases := []struct {
		ref, version, want string
	}{
		// Catalog returns untagged repo + version field (the dockercompose 404 case).
		{"registry.adversarylabs.ai/adversarylabs/dockercompose", "0.0.5", "registry.adversarylabs.ai/adversarylabs/dockercompose:0.0.5"},
		{"adversarylabs/go-cli", "0.0.15", "adversarylabs/go-cli:0.0.15"},
		// Already tagged / digested: leave alone.
		{"registry.example/adversarylabs/go-cli:0.0.14", "0.0.15", "registry.example/adversarylabs/go-cli:0.0.14"},
		{"registry.example/adversarylabs/go-cli@sha256:abc", "0.0.15", "registry.example/adversarylabs/go-cli@sha256:abc"},
		// No version: unchanged (OCI layer may still default to latest).
		{"registry.example/adversarylabs/go-cli", "", "registry.example/adversarylabs/go-cli"},
		// host:port must not look like a tag when appending.
		{"localhost:5000/adversarylabs/go-cli", "1.0.0", "localhost:5000/adversarylabs/go-cli:1.0.0"},
		{"localhost:5000/adversarylabs/go-cli:1.0.0", "2.0.0", "localhost:5000/adversarylabs/go-cli:1.0.0"},
	}
	for _, tc := range cases {
		if got := catalogPullReference(tc.ref, tc.version); got != tc.want {
			t.Errorf("catalogPullReference(%q, %q) = %q, want %q", tc.ref, tc.version, got, tc.want)
		}
	}
}

func TestEnsureAccessibleAdversariesPinsCatalogVersionOnUntaggedRef(t *testing.T) {
	// Capture the registry path so we know ensure requested :0.0.5, not :latest.
	var seenPath string
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		http.NotFound(w, r)
	}))
	defer registry.Close()
	regHost := strings.TrimPrefix(registry.URL, "http://")
	// Untagged repository reference — the shape the real catalog returns for dockercompose.
	ref := regHost + "/adversarylabs/dockercompose"

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/search" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"results":[
				{"name":"adversarylabs/dockercompose","version":"0.0.5","reference":"` + ref + `"}
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

	err = ensureAccessibleAdversaries(context.Background(), app, api.URL, "work", &stderr)
	var syncErr *accessibleAdversarySyncError
	if !errors.As(err, &syncErr) || syncErr.Failed != 1 || syncErr.Total != 1 {
		t.Fatalf("err = %#v, want one failed accessible adversary", err)
	}
	// OCI distribution resolves tags via .../manifests/<tag>.
	if !strings.Contains(seenPath, "/manifests/0.0.5") {
		t.Fatalf("expected pull of tagged 0.0.5, registry saw path %q; stderr=%q", seenPath, stderr.String())
	}
	if strings.Contains(seenPath, "/manifests/latest") {
		t.Fatalf("must not fall back to :latest when catalog version is set; path=%q", seenPath)
	}
	if !strings.Contains(stderr.String(), "0.0.5") {
		t.Fatalf("status should show catalog version, got %q", stderr.String())
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

	err = ensureAccessibleAdversaries(context.Background(), app, server.URL, "work", &stderr)
	var syncErr *accessibleAdversarySyncError
	if !errors.As(err, &syncErr) || syncErr.Failed != 2 || syncErr.Total != 2 {
		t.Fatalf("err = %#v, want two failed accessible adversaries", err)
	}
	out := stderr.String()
	if !strings.Contains(out, "Ensuring 2 accessible adversaries") {
		t.Fatalf("expected ensure header, got %q", out)
	}
	if !strings.Contains(out, "go-cli") || !strings.Contains(out, "0.0.15") {
		t.Fatalf("expected newest go-cli row, got %q", out)
	}
	if strings.Contains(out, "0.0.14") {
		t.Fatalf("stale go-cli version should not appear, got %q", out)
	}
	if !strings.Contains(out, "failed:") || !strings.Contains(out, "2 failed") {
		t.Fatalf("expected failed status summary, got %q", out)
	}
	// Quiet path: do not spam per-item "Pulling manifest..." on ensure.
	if strings.Contains(out, "Pulling manifest") {
		t.Fatalf("ensure should not print pull progress spam, got %q", out)
	}
}

func TestEnsureAccessibleAdversariesStatusLines(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/search" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"results":[
				{"name":"adversarylabs/go-cli","version":"0.0.15","reference":"registry.example/adversarylabs/go-cli:0.0.15"},
				{"name":"adversarylabs/dockerfile","version":"0.0.8","reference":"registry.example/adversarylabs/dockerfile:0.0.8"}
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

	err = ensureAccessibleAdversaries(context.Background(), app, server.URL, "work", &stderr)
	var syncErr *accessibleAdversarySyncError
	if !errors.As(err, &syncErr) || syncErr.Failed != 2 || syncErr.Total != 2 {
		t.Fatalf("err = %#v, want two failed accessible adversaries", err)
	}
	out := stderr.String()
	if !strings.Contains(out, "adversarylabs/go-cli") && !strings.Contains(out, "go-cli") {
		t.Fatalf("expected go-cli status line, got %q", out)
	}
	if !strings.Contains(out, "dockerfile") {
		t.Fatalf("expected dockerfile status line, got %q", out)
	}
	if !strings.Contains(out, "✗") && !strings.Contains(out, "failed:") {
		t.Fatalf("expected failure mark, got %q", out)
	}
}

type concurrentResolveRegistry struct {
	started chan string
	release chan struct{}
}

func (*concurrentResolveRegistry) SetPlainHTTP(bool) {}
func (*concurrentResolveRegistry) PushSources(context.Context, oci.Reference, []byte, []oci.SourceBlob) (string, error) {
	return "", errors.New("unexpected push")
}
func (*concurrentResolveRegistry) PushAdversaryManifestReferrer(context.Context, oci.Reference, string, []byte) (string, string, error) {
	return "", "", errors.New("unexpected referrer push")
}
func (*concurrentResolveRegistry) PushAttachedReferrer(context.Context, oci.Reference, string, string, string, string, []byte) (string, string, error) {
	return "", "", errors.New("unexpected referrer push")
}
func (*concurrentResolveRegistry) PullSources(context.Context, oci.Reference) (*oci.PulledSources, error) {
	return nil, errors.New("unexpected pull")
}
func (*concurrentResolveRegistry) GetOfficialSignatureReferrer(context.Context, oci.Reference, string) ([]byte, error) {
	return nil, errors.New("unexpected signature pull")
}
func (*concurrentResolveRegistry) GetNamespaceSignatureReferrer(context.Context, oci.Reference, string) ([]byte, error) {
	return nil, errors.New("unexpected signature pull")
}
func (*concurrentResolveRegistry) GetNamespaceTrustReferrer(context.Context, oci.Reference, string) ([]byte, error) {
	return nil, errors.New("unexpected trust pull")
}
func (r *concurrentResolveRegistry) Resolve(ctx context.Context, ref oci.Reference) (string, error) {
	select {
	case r.started <- ref.Repository:
	case <-ctx.Done():
		return "", ctx.Err()
	}
	select {
	case <-r.release:
		return "", errors.New("fixture resolve failure")
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

type concurrentRegistryFactory struct {
	registry application.OCIRegistry
	identity string
}

func (f concurrentRegistryFactory) BindingIdentity() string { return f.identity }

func (f concurrentRegistryFactory) New(string, string) (application.OCIRegistry, error) {
	return f.registry, nil
}

func TestEnsureAccessibleAdversariesPullsConcurrently(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/search" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[
			{"name":"one","version":"1.0.0","reference":"registry.example/team/one:1.0.0"},
			{"name":"two","version":"1.0.0","reference":"registry.example/team/two:1.0.0"}
		]}`))
	}))
	defer api.Close()

	var stdout, stderr bytes.Buffer
	base := lifecycleTestApp(t, repository.Repository{Root: t.TempDir()}, &stdout, &stderr).Dependencies()
	store := base.Auth.(processAuthStore).ConfigStore
	if err := store.SetAuth(adversarylabs.AuthKey(api.URL, "work"), adversarylabs.Auth{Token: "token"}); err != nil {
		t.Fatal(err)
	}
	base.API = processAPIFactory{store: store, http: api.Client()}
	registry := &concurrentResolveRegistry{
		started: make(chan string, 2),
		release: make(chan struct{}),
	}
	base.Registries = concurrentRegistryFactory{registry: registry, identity: store.Path}
	app, err := application.New(base)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { done <- ensureAccessibleAdversaries(t.Context(), app, api.URL, "work", &stderr) }()
	for i := 0; i < 2; i++ {
		select {
		case <-registry.started:
		case <-time.After(2 * time.Second):
			t.Fatal("catalog pulls did not overlap")
		}
	}
	close(registry.release)
	err = <-done
	var syncErr *accessibleAdversarySyncError
	if !errors.As(err, &syncErr) || syncErr.Failed != 2 {
		t.Fatalf("err = %v, want two pull failures", err)
	}
}

func TestRenderEnsureResultsInIndexOrder(t *testing.T) {
	results := make(chan ensureResult, 2)
	results <- ensureResult{job: ensureJob{index: 1}}
	results <- ensureResult{job: ensureJob{index: 0}}

	var got []int
	renderEnsureResults(2, results, func(result ensureResult) {
		got = append(got, result.job.index)
	})
	if len(got) != 2 || got[0] != 0 || got[1] != 1 {
		t.Fatalf("render order = %v, want [0 1]", got)
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
