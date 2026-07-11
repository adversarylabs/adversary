package cmd

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	internaladversary "github.com/adversarylabs/adversary/internal/adversary"
	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/internal/dependencies"
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

type processPaths struct{ data string }

func (p processPaths) DataDir() (string, error)   { return p.data, nil }
func (p processPaths) ConfigDir() (string, error) { return p.data, nil }
func (processPaths) TempDir() string              { return os.TempDir() }

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
	return internaladversary.RunOptions{AdversaryRef: opts.AdversaryRef, RepoPath: opts.RepoPath, BaseRef: opts.BaseRef, HeadRef: opts.HeadRef, Builder: opts.Builder, Format: opts.Format, Force: opts.Force, KeepTemp: opts.KeepTemp, NoNetwork: opts.NoNetwork, Verbose: opts.Verbose, IncludeSuppressed: opts.IncludeSuppressed, Shell: opts.Shell, AllFiles: opts.AllFiles, AllowUnsafeHostExecution: opts.AllowUnsafeHostExecution}
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
	return adversarylabs.Client{BaseURL: strings.TrimRight(base, "/"), HTTP: f.http, Store: f.store}
}

type processOCIRegistry struct{ *oci.HTTPRegistry }

func (r processOCIRegistry) SetPlainHTTP(v bool) { r.PlainHTTP = v }

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
	return application.New(application.Dependencies{Stdin: stdin, Stdout: stdout, Stderr: stderr, Clock: newSystemClock(), Env: dependencies.Environment{LookupFunc: os.LookupEnv}, Config: processConfig{}, Paths: processPaths{data: resolver.Repository.Root}, HTTP: dependencies.HTTPClient{DoFunc: http.DefaultClient.Do}, Credentials: docker, Auth: authStore, API: apiFactory, Registries: registryFactory, DefaultAPIURL: apiURL, RegistryHost: host, RegistryNS: namespace, Repository: processRepository{resolver.Repository}, Resolver: processResolver{resolver: resolver}, Runtime: processRuntime{resolver: resolver}, Browser: dependencies.Browser{OpenFunc: func(ctx context.Context, u string) error { return openBrowser(u) }}, TTY: processTTY{}})
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
