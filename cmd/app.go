package cmd

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	internaladversary "github.com/adversarylabs/adversary/internal/adversary"
	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/internal/dependencies"
	internalpaths "github.com/adversarylabs/adversary/internal/paths"
	"github.com/adversarylabs/adversary/pkg/adversarylabs"
	"github.com/adversarylabs/adversary/pkg/oci"
	"github.com/adversarylabs/adversary/pkg/pack"
	"github.com/adversarylabs/adversary/pkg/repository"
	"golang.org/x/term"
)

type processTimer struct{ *time.Timer }

func (t processTimer) C() <-chan time.Time { return t.Timer.C }
func newSystemClock() application.Clock {
	return dependencies.Clock{NowFunc: time.Now, TimerFunc: func(d time.Duration) application.Timer { return processTimer{time.NewTimer(d)} }}
}

type processConfig struct{}

func (processConfig) Get(context.Context, string) (string, error) { return "", nil }
func (processConfig) Set(context.Context, string, string) error   { return nil }

type processPaths struct{ data, config string }

func (p processPaths) DataDir() (string, error)   { return p.data, nil }
func (p processPaths) ConfigDir() (string, error) { return p.config, nil }
func (processPaths) TempDir() string              { return internalpaths.TempDir() }

type processResolver struct{ resolver internaladversary.Resolver }

func (p processResolver) Resolve(ctx context.Context, value string) (application.Resolution, error) {
	got, err := p.resolver.Resolve(value)
	return toApplicationResolution(got), err
}
func (p processResolver) Lookup(ctx context.Context, value string) (application.Resolution, error) {
	got, err := p.resolver.Lookup(value)
	return toApplicationResolution(got), err
}
func toApplicationResolution(got internaladversary.Resolution) application.Resolution {
	return application.Resolution{CanonicalReference: got.CanonicalReference, Digest: got.Digest, Path: got.Path, Local: got.Local, Record: got.Record}
}
func (p processResolver) BindingIdentity() string { return p.resolver.Repository.RootPath() }
func (p processResolver) ResolveRecord(value string) (repository.Record, error) {
	return p.resolver.Repository.Resolve(value)
}
func (p processResolver) HasExact(value string) (bool, error) {
	return p.resolver.Repository.HasExact(value)
}
func (p processResolver) Entries(limit int) ([]repository.Entry, error) {
	return p.resolver.Repository.Entries(limit)
}
func (p processResolver) Payload(record repository.Record) ([]byte, []oci.Blob, []byte, error) {
	return p.resolver.Repository.Payload(record)
}
func (p processResolver) ImportPacked(a pack.Artifact, ref string) (repository.Record, error) {
	return p.resolver.ImportPacked(a, ref)
}
func (p processResolver) ImportPulled(a oci.PulledArtifact) (repository.Record, error) {
	return p.resolver.ImportPulled(a)
}
func (p processResolver) UpdateRef(ref, oldDigest, newDigest string) error {
	return p.resolver.Repository.UpdateRef(ref, oldDigest, newDigest)
}

type processRepository struct{ repository.Repository }

func (p processRepository) BindingIdentity() string { return p.RootPath() }

type processRuntime struct{ resolver internaladversary.Resolver }

func (p processRuntime) BindingIdentity() string { return p.resolver.Repository.RootPath() }
func (p processRuntime) Run(ctx context.Context, opts application.AdversaryRunOptions) error {
	r := internaladversary.Runner{Stdout: opts.Stdout, Stderr: opts.Stderr, Repository: &p.resolver.Repository, Resolver: &p.resolver, RequireInjectedResolver: true}
	return r.Run(ctx, toInternalRunOptions(opts))
}
func (p processRuntime) Inspect(ctx context.Context, opts application.AdversaryRunOptions) error {
	r := internaladversary.Runner{Stdout: opts.Stdout, Stderr: opts.Stderr, Repository: &p.resolver.Repository, Resolver: &p.resolver, RequireInjectedResolver: true}
	return r.Inspect(toInternalRunOptions(opts))
}
func toInternalRunOptions(opts application.AdversaryRunOptions) internaladversary.RunOptions {
	return internaladversary.RunOptions{AdversaryRef: opts.AdversaryRef, RepoPath: opts.RepoPath, BaseRef: opts.BaseRef, HeadRef: opts.HeadRef, Builder: opts.Builder, Format: opts.Format, Force: opts.Force, KeepTemp: opts.KeepTemp, NoNetwork: opts.NoNetwork, Verbose: opts.Verbose, IncludeSuppressed: opts.IncludeSuppressed, Shell: opts.Shell, AllFiles: opts.AllFiles, AllowUnsafeHostExecution: opts.AllowUnsafeHostExecution, Build: opts.Build, RunTimeout: opts.RunTimeout, BuildTimeout: opts.BuildTimeout}
}

type processTTY struct{}

func (processTTY) Interactive(r io.Reader) bool {
	f, ok := r.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

type processAPIFactory struct {
	store adversarylabs.ConfigStore
	http  *http.Client
}

func (f processAPIFactory) BindingIdentity() string { return f.store.Path }

func (f processAPIFactory) New(base string) application.APIClient {
	return classifiedAPIClient{inner: adversarylabs.Client{BaseURL: strings.TrimRight(base, "/"), HTTP: f.http, Store: f.store}}
}

type classifiedAPIClient struct{ inner application.APIClient }

func authError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return &application.Error{Operation: operation, Kind: "auth", Err: err}
}
func (c classifiedAPIClient) BeginLogin(ctx context.Context, o adversarylabs.LoginOptions) (adversarylabs.DeviceLogin, error) {
	v, e := c.inner.BeginLogin(ctx, o)
	return v, authError("begin login", e)
}
func (c classifiedAPIClient) LoginWithPassword(ctx context.Context, o adversarylabs.PasswordLoginOptions) (adversarylabs.TokenResponse, error) {
	v, e := c.inner.LoginWithPassword(ctx, o)
	return v, authError("password login", e)
}
func (c classifiedAPIClient) BrowserLoginURL(o adversarylabs.BrowserLoginOptions) (string, error) {
	v, e := c.inner.BrowserLoginURL(o)
	return v, authError("browser login URL", e)
}
func (c classifiedAPIClient) ExchangeCode(ctx context.Context, a, b, d string) (adversarylabs.TokenResponse, error) {
	v, e := c.inner.ExchangeCode(ctx, a, b, d)
	return v, authError("exchange login code", e)
}
func (c classifiedAPIClient) PollToken(ctx context.Context, token string) (adversarylabs.TokenResponse, error) {
	v, e := c.inner.PollToken(ctx, token)
	return v, authError("poll login token", e)
}
func (c classifiedAPIClient) Revoke(ctx context.Context, token string) error {
	return authError("revoke token", c.inner.Revoke(ctx, token))
}
func (c classifiedAPIClient) Search(ctx context.Context, token, query string) ([]adversarylabs.SearchResult, error) {
	v, e := c.inner.Search(ctx, token, query)
	return v, authError("search API", e)
}
func (c classifiedAPIClient) Whoami(ctx context.Context, token string) (adversarylabs.WhoamiResponse, error) {
	v, e := c.inner.Whoami(ctx, token)
	return v, authError("whoami API", e)
}

type processOCIRegistry struct{ *oci.HTTPRegistry }

func (r processOCIRegistry) SetPlainHTTP(v bool) { r.PlainHTTP = v }
func networkError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return &application.Error{Operation: operation, Kind: "network", Err: err}
}
func (r processOCIRegistry) Push(ctx context.Context, ref oci.Reference, manifest []byte, blobs []oci.Blob) (string, error) {
	v, e := r.HTTPRegistry.Push(ctx, ref, manifest, blobs)
	return v, networkError("OCI push", e)
}
func (r processOCIRegistry) PushAdversaryManifestReferrer(ctx context.Context, ref oci.Reference, digest string, manifest []byte) (string, string, error) {
	a, b, e := r.HTTPRegistry.PushAdversaryManifestReferrer(ctx, ref, digest, manifest)
	return a, b, networkError("OCI referrer push", e)
}
func (r processOCIRegistry) Pull(ctx context.Context, ref oci.Reference) (oci.PulledArtifact, error) {
	v, e := r.HTTPRegistry.Pull(ctx, ref)
	return v, networkError("OCI pull", e)
}
func (r processOCIRegistry) Resolve(ctx context.Context, ref oci.Reference) (string, error) {
	v, e := r.HTTPRegistry.Resolve(ctx, ref)
	return v, networkError("OCI resolve", e)
}

type processAuthStore struct{ adversarylabs.ConfigStore }

func (s processAuthStore) BindingIdentity() string { return s.Path }

type processRegistryFactory struct {
	store                  application.AuthStore
	docker                 application.Credentials
	host, realm, namespace string
	debug                  io.Writer
	identity               string
}

func (f processRegistryFactory) BindingIdentity() string { return f.identity }

func (f processRegistryFactory) New(apiURL, profile string) (application.OCIRegistry, error) {
	r := oci.NewHTTPRegistry()
	r.Debug = f.debug
	r.BearerRealm = registryAuthRealm(apiURL)
	r.BearerService = f.host
	if realm, err := url.Parse(r.BearerRealm); err == nil && realm.Host != "" {
		r.TokenAuthorities[f.host] = oci.TokenAuthority{Origin: realm.Scheme + "://" + realm.Host, Service: f.host}
	}
	auth, ok, err := scopedAuth(f.store, apiURL, profile, f.host)
	if err != nil {
		return nil, err
	}
	stores := oci.ChainCredentialStore{f.docker}
	if ok {
		stores = append(oci.ChainCredentialStore{scopedCredentialStore{registry: f.host, token: auth.Token}}, stores...)
	}
	r.Credentials = stores
	return processOCIRegistry{r}, nil
}
func (processTTY) ReadSecret(ctx context.Context, r io.Reader, w io.Writer) ([]byte, error) {
	_ = ctx
	fmt.Fprint(w, "Password: ")
	f, ok := r.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		fmt.Fprintln(w)
		return nil, fmt.Errorf("interactive password input requires a terminal; use --password-stdin")
	}
	secret, err := term.ReadPassword(int(f.Fd()))
	fmt.Fprintln(w)
	return secret, err
}

func newProcessApp(stdin io.Reader, stdout, stderr io.Writer) (*application.App, error) {
	resolver, err := internaladversary.DefaultResolver()
	if err != nil {
		return nil, err
	}
	store, err := adversarylabs.DefaultConfigStore()
	if err != nil {
		return nil, err
	}
	configDir := filepath.Dir(store.Path)
	apiURL := envDefault("ADVERSARY_API_URL", adversarylabs.DefaultAPIURL)
	host := envDefault("ADVERSARY_REGISTRY_HOST", adversarylabs.DefaultRegistry)
	namespace := envDefault("ADVERSARY_REGISTRY_NAMESPACE", "")
	var debug io.Writer
	if value, ok := os.LookupEnv("ADVERSARY_OCI_DEBUG"); ok && strings.TrimSpace(value) != "" {
		debug = stderr
	}
	docker := oci.DockerCredentialStore{}
	authStore := processAuthStore{store}
	apiFactory := processAPIFactory{store: store, http: http.DefaultClient}
	registryFactory := processRegistryFactory{store: authStore, docker: docker, host: host, namespace: namespace, debug: debug, identity: store.Path}
	return application.New(application.Dependencies{Stdin: stdin, Stdout: stdout, Stderr: stderr, Clock: newSystemClock(), Env: dependencies.Environment{LookupFunc: os.LookupEnv}, Config: processConfig{}, Paths: processPaths{data: resolver.Repository.Root, config: configDir}, HTTP: dependencies.HTTPClient{DoFunc: http.DefaultClient.Do}, Credentials: docker, Auth: authStore, API: apiFactory, Registries: registryFactory, DefaultAPIURL: apiURL, RegistryHost: host, RegistryNS: namespace, Repository: processRepository{resolver.Repository}, Resolver: processResolver{resolver: resolver}, Runtime: processRuntime{resolver: resolver}, Browser: dependencies.Browser{OpenFunc: func(ctx context.Context, u string) error { return openBrowser(u) }}, TTY: processTTY{}})
}

func envDefault(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok && strings.TrimSpace(value) != "" {
		return strings.TrimRight(strings.TrimSpace(value), "/")
	}
	return strings.TrimRight(fallback, "/")
}

func openBrowser(url string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	default:
		return exec.Command("xdg-open", url).Start()
	}
}
