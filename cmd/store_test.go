package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	internaladversary "github.com/adversarylabs/adversary/internal/adversary"
	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/internal/dependencies"
	"github.com/adversarylabs/adversary/pkg/adversarylabs"
	"github.com/adversarylabs/adversary/pkg/oci"
	"github.com/adversarylabs/adversary/pkg/pack"
	"github.com/adversarylabs/adversary/pkg/repository"
)

type exactSecretTTY struct{ secret []byte }

func (exactSecretTTY) Interactive(io.Reader) bool { return true }
func (t exactSecretTTY) ReadSecret(context.Context, io.Reader, io.Writer) ([]byte, error) {
	return append([]byte(nil), t.secret...), nil
}

type fakeTimer struct {
	ch      chan time.Time
	stopped *bool
}

func (t fakeTimer) C() <-chan time.Time { return t.ch }
func (t fakeTimer) Stop() bool          { *t.stopped = true; return true }

type fakeClock struct {
	stopped *bool
	now     time.Time
}

func (c fakeClock) Now() time.Time { return c.now }
func (c fakeClock) NewTimer(time.Duration) application.Timer {
	return fakeTimer{ch: make(chan time.Time), stopped: c.stopped}
}

func TestLoginInjectedTTYPreservesWhitespace(t *testing.T) {
	var got string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Password string `json:"password"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		got = body.Password
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":"ok"}`))
	}))
	defer s.Close()
	repo := repository.Repository{Root: t.TempDir()}
	var out, errOut bytes.Buffer
	base := lifecycleTestApp(t, repo, &out, &errOut).Dependencies()
	base.TTY = exactSecretTTY{secret: []byte("  pass word\t\n")}
	app, err := application.New(base)
	if err != nil {
		t.Fatal(err)
	}
	cmd := NewRootCommandWithApp(app)
	cmd.SetArgs([]string{"--api-url", s.URL, "login", "--email-address", "a@example.test"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if got != "  pass word\t\n" {
		t.Fatalf("password=%q", got)
	}
}

func TestInjectedAuthSearchAndWhoamiNeedNoProcessEnvironment(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/search":
			_, _ = w.Write([]byte(`{"results":[{"reference":"acme/reviewer","version":"1.2.3"}]}`))
		case "/v1/auth/whoami":
			_, _ = w.Write([]byte(`{"name":"Injected User","email_address":"user@example.test","subscription":{"name":"Team","status":"active"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	repo := repository.Repository{Root: t.TempDir()}
	var out, errOut bytes.Buffer
	base := lifecycleTestApp(t, repo, &out, &errOut).Dependencies()
	store := base.Auth.(processAuthStore).ConfigStore
	if err := store.SetAuth(adversarylabs.AuthKey(server.URL, "work"), adversarylabs.Auth{Token: "injected-token"}); err != nil {
		t.Fatal(err)
	}
	base.API = processAPIFactory{store: store, http: server.Client()}
	base.Registries = processRegistryFactory{store: store, docker: base.Credentials, host: base.RegistryHost, identity: store.Path}
	app, err := application.New(base)
	if err != nil {
		t.Fatal(err)
	}

	search := NewRootCommandWithApp(app)
	search.SetArgs([]string{"--api-url", server.URL, "--profile", "work", "search", "reviewer"})
	if err := search.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "NAME") || !strings.Contains(out.String(), "acme/reviewer") || !strings.Contains(out.String(), "1.2.3") {
		t.Fatalf("search output=%q", out.String())
	}
	out.Reset()
	whoami := NewRootCommandWithApp(app)
	whoami.SetArgs([]string{"--api-url", server.URL, "--profile", "work", "whoami"})
	if err := whoami.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Name: Injected User") {
		t.Fatalf("whoami output=%q", out.String())
	}
}

func TestInjectedClockStopsTimerOnDeviceCancellation(t *testing.T) {
	stopped := false
	client := adversarylabs.Client{BaseURL: "https://api.test", HTTP: &http.Client{Transport: cmdRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		return jsonHTTPResponse(http.StatusBadGateway, `{}`), nil
	})}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := waitForLogin(ctx, fakeClock{stopped: &stopped, now: time.Now()}, client, adversarylabs.DeviceLogin{DeviceCode: "d", ExpiresIn: 60, Interval: 1})
		done <- err
	}()
	time.Sleep(10 * time.Millisecond)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
	if !stopped {
		t.Fatal("timer not stopped")
	}
}

func TestInjectedBrowserIsCalled(t *testing.T) {
	called := false
	ctx, cancel := context.WithCancel(context.Background())
	browser := dependencies.Browser{OpenFunc: func(context.Context, string) error { called = true; cancel(); return nil }}
	client := adversarylabs.Client{BaseURL: "https://api.test", HTTP: &http.Client{Transport: cmdRoundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("unexpected request") })}}
	_, err := loginWithBrowser(ctx, browser, &bytes.Buffer{}, client, &loginOptions{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
	if !called {
		t.Fatal("browser was not called")
	}
}

func TestProcessAppResolverRepositoryBindingAccepted(t *testing.T) {
	t.Setenv("ADVERSARY_DATA_DIR", t.TempDir())
	app, err := newProcessApp(&bytes.Buffer{}, &bytes.Buffer{}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	_ = app
}

func TestLogoutPreservesCredentialReplacedDuringRevocation(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/revoke" {
			http.NotFound(w, r)
			return
		}
		close(started)
		<-release
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	repo := repository.Repository{Root: t.TempDir()}
	var out, errOut bytes.Buffer
	base := lifecycleTestApp(t, repo, &out, &errOut).Dependencies()
	store := adversarylabs.ConfigStore{Path: filepath.Join(t.TempDir(), "config.json")}
	key := adversarylabs.AuthKey(server.URL, "default")
	stale := adversarylabs.Auth{Token: "stale", ClientID: "old", RegistryHost: adversarylabs.DefaultRegistry}
	fresh := adversarylabs.Auth{Token: "fresh", ClientID: "new", RegistryHost: adversarylabs.DefaultRegistry}
	if err := store.SetAuth(key, stale); err != nil {
		t.Fatal(err)
	}
	base.Auth = processAuthStore{store}
	base.API = processAPIFactory{store: store, http: server.Client()}
	base.Registries = processRegistryFactory{store: base.Auth, docker: base.Credentials, host: adversarylabs.DefaultRegistry, identity: store.Path}
	app, err := application.New(base)
	if err != nil {
		t.Fatal(err)
	}
	command := NewRootCommandWithApp(app)
	command.SetArgs([]string{"--api-url", server.URL, "logout"})
	done := make(chan error, 1)
	go func() { done <- command.Execute() }()
	<-started
	if err := store.SetAuth(key, fresh); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; !errors.Is(err, adversarylabs.ErrAuthCAS) {
		t.Fatalf("logout error=%v", err)
	}
	got, ok, err := store.ExactAuthE(key)
	if err != nil || !ok || got != fresh {
		t.Fatalf("got=%#v ok=%v err=%v", got, ok, err)
	}
}

func lifecycleTestApp(t *testing.T, repo repository.Repository, stdout, stderr *bytes.Buffer) *application.App {
	t.Helper()
	store := adversarylabs.ConfigStore{Path: filepath.Join(t.TempDir(), "config.json")}
	docker := oci.DockerCredentialStore{}
	resolver := internaladversary.Resolver{Repository: repo}
	app, err := application.New(application.Dependencies{Stdin: &bytes.Buffer{}, Stdout: stdout, Stderr: stderr, Clock: dependencies.Clock{NowFunc: func() time.Time { return time.Unix(1, 0) }, TimerFunc: func(time.Duration) application.Timer { return processTimer{time.NewTimer(time.Hour)} }}, Env: dependencies.Environment{LookupFunc: func(string) (string, bool) { return "", false }}, Config: processConfig{}, Paths: processPaths{data: repo.Root}, HTTP: dependencies.HTTPClient{DoFunc: http.DefaultClient.Do}, Credentials: docker, Auth: processAuthStore{store}, API: processAPIFactory{store: store, http: http.DefaultClient}, Registries: processRegistryFactory{store: store, docker: docker, host: adversarylabs.DefaultRegistry, identity: store.Path}, DefaultAPIURL: adversarylabs.DefaultAPIURL, RegistryHost: adversarylabs.DefaultRegistry, Repository: processRepository{repo}, Resolver: processResolver{resolver: resolver}, Runtime: processRuntime{resolver: resolver}, Browser: dependencies.Browser{OpenFunc: func(context.Context, string) error { return nil }}, TTY: processTTY{}})
	if err != nil {
		t.Fatal(err)
	}
	return app
}

func TestStoreLifecycleJSONAndConfirmation(t *testing.T) {
	repo := repository.Repository{Root: t.TempDir()}
	project := t.TempDir()
	writeProject(t, project)
	a, err := pack.Create(context.Background(), pack.Options{Dir: project})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.ImportPacked(a, ""); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	app := lifecycleTestApp(t, repo, &out, &errOut)
	check := NewRootCommandWithApp(app)
	check.SetArgs([]string{"store", "check", "--json"})
	if err := check.Execute(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out.Bytes(), []byte(`"healthy":true`)) {
		t.Fatalf("output=%s", out.String())
	}
	if errOut.Len() != 0 {
		t.Fatalf("JSON stderr=%q", errOut.String())
	}
	out.Reset()
	gc := NewRootCommandWithApp(app)
	gc.SetArgs([]string{"store", "gc", "--json"})
	if err := gc.Execute(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out.Bytes(), []byte(`"dryRun":true`)) {
		t.Fatalf("output=%s", out.String())
	}
	apply := NewRootCommandWithApp(app)
	apply.SetArgs([]string{"store", "gc", "--apply"})
	if err := apply.Execute(); err == nil || !application.IsKind(err, "confirmation") {
		t.Fatal("destructive GC did not require confirmation")
	}
	refRec, err := repo.ImportPacked(a, "registry.example/team/test:1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	del := NewRootCommandWithApp(app)
	del.SetArgs([]string{"store", "ref-delete", "registry.example/team/test:1.0.0", refRec.Digest + "bad", "--yes"})
	if err := del.Execute(); err == nil || !application.IsKind(err, "repository") {
		t.Fatalf("CAS delete error=%v", err)
	}
}

func TestApplicationRejectsMismatchedResolverAtConstruction(t *testing.T) {
	dataA := t.TempDir()
	repoA := repository.Repository{Root: filepath.Join(dataA, "repository-v1")}
	if err := os.MkdirAll(repoA.Root, 0700); err != nil {
		t.Fatal(err)
	}
	repoB := repository.Repository{Root: t.TempDir()}
	t.Setenv("ADVERSARY_DATA_DIR", dataA)
	t.Setenv("HOME", dataA)
	ref := "registry.example/team/tool:1.0.0"
	for _, item := range []struct {
		repo repository.Repository
		body string
	}{{repoA, "a"}, {repoB, "b"}} {
		project := t.TempDir()
		writeProject(t, project)
		if err := os.WriteFile(filepath.Join(project, "dist", "index.js"), []byte(item.body), 0644); err != nil {
			t.Fatal(err)
		}
		a, err := pack.Create(context.Background(), pack.Options{Dir: project})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := item.repo.ImportPacked(a, ref); err != nil {
			t.Fatal(err)
		}
	}
	var out, errOut bytes.Buffer
	base := lifecycleTestApp(t, repoB, &out, &errOut).Dependencies()
	deps := base
	deps.Resolver = processResolver{resolver: internaladversary.Resolver{Repository: repoA}}
	if _, err := application.New(deps); err == nil || !application.IsKind(err, "invalid-dependency") {
		t.Fatalf("error=%v", err)
	}
}
