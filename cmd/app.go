package cmd

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	internaladversary "github.com/adversarylabs/adversary/internal/adversary"
	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/internal/dependencies"
	"github.com/adversarylabs/adversary/internal/initproject"
	internalpaths "github.com/adversarylabs/adversary/internal/paths"
	"github.com/adversarylabs/adversary/pkg/adversarylabs"
	"github.com/adversarylabs/adversary/pkg/manifest"
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

type processProjects struct {
	references    application.References
	build         pack.BuildEnvironment
	buildStateDir string
}

func (processProjects) Init(opts application.ProjectInitOptions) (application.ProjectInitResult, error) {
	result, err := initproject.Create(initproject.Options{Destination: opts.Destination, SDK: opts.SDK})
	return application.ProjectInitResult{Location: result.Location, SDK: result.SDK}, err
}
func (processProjects) RenderInit(w io.Writer, result application.ProjectInitResult, destination string) {
	initproject.RenderSuccess(w, initproject.Result{Location: result.Location, SDK: result.SDK}, destination)
}
func (processProjects) Validate(ctx context.Context, value string, resolver application.Resolver) (application.ProjectValidation, error) {
	path, err := filepath.Abs(value)
	if err != nil {
		return application.ProjectValidation{}, &application.ProjectError{Code: "invalid_path", Path: value, Err: fmt.Errorf("validate path %q: %w", value, err)}
	}
	if _, statErr := os.Stat(path); statErr != nil && os.IsNotExist(statErr) {
		resolution, resolveErr := resolver.Resolve(ctx, value)
		if resolveErr != nil {
			return application.ProjectValidation{}, &application.ProjectError{Code: "unresolved_reference", Path: value, Err: fmt.Errorf("validate path or reference %q: %w", value, resolveErr)}
		}
		path = resolution.Path
	}
	root := path
	info, err := os.Stat(path)
	if err != nil {
		return application.ProjectValidation{}, &application.ProjectError{Code: "unreadable_path", Path: path, Err: fmt.Errorf("validate %q: %w", value, err)}
	}
	if info.IsDir() {
		path = filepath.Join(path, manifest.FileName)
	} else {
		root = filepath.Dir(path)
	}
	m, err := manifest.Load(path)
	if err != nil {
		return application.ProjectValidation{}, &application.ProjectError{Code: "invalid_manifest", Path: path, Err: fmt.Errorf("validate manifest v1 %q: %w", path, err)}
	}
	if err := m.ValidateProject(root); err != nil {
		return application.ProjectValidation{}, &application.ProjectError{Code: "invalid_project", Path: root, Err: fmt.Errorf("validate project v1 %q: %w", root, err)}
	}
	return application.ProjectValidation{Path: path, Name: m.Name, Runtime: m.Runtime.Name}, nil
}

func (p processProjects) Check(opts pack.Options) (pack.Preflight, error) {
	opts.ParseReference = p.references.Parse
	return pack.Check(opts)
}
func (p processProjects) Pack(ctx context.Context, opts pack.Options) (pack.Artifact, error) {
	opts.ParseReference = p.references.Parse
	opts.BuildProject = composedBuildProject(p.build, p.buildStateDir)
	return pack.Create(ctx, opts)
}

func composedBuildProject(environment pack.BuildEnvironment, buildStateDir string) func(context.Context, pack.BuildOptions) error {
	return func(ctx context.Context, options pack.BuildOptions) error {
		options.BuildStateDir = buildStateDir
		return pack.BuildProjectWithEnvironment(ctx, options, environment)
	}
}

type processReferences struct{ registry, namespace string }

func (p processReferences) Parse(value string) (oci.Reference, error) {
	return oci.ParseReferenceWithDefaults(value, p.registry, p.namespace)
}

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
func (p processResolver) CanonicalReferenceFor(digest, preferred string) (string, error) {
	return p.resolver.Repository.CanonicalReferenceFor(digest, preferred)
}
func (p processResolver) Inventory(record repository.Record) ([]pack.File, error) {
	return p.resolver.Repository.Inventory(record)
}
func (p processResolver) PayloadSources(record repository.Record) (*repository.PayloadLease, error) {
	return p.resolver.Repository.PayloadSources(record)
}
func (p processResolver) ImportPacked(a pack.Artifact, ref string) (repository.Record, error) {
	return p.resolver.ImportPacked(a, ref)
}
func (p processResolver) ImportSources(in repository.SourceImport) (repository.Record, error) {
	return p.resolver.Repository.ImportSources(in)
}
func (p processResolver) CommitEquivalentManifest(source, target string, manifest []byte) (repository.Record, error) {
	return p.resolver.Repository.CommitEquivalentManifest(source, target, manifest)
}
func (p processResolver) UpdateRef(ref, oldDigest, newDigest string) error {
	return p.resolver.Repository.UpdateRef(ref, oldDigest, newDigest)
}

type processRepository struct{ repository.Repository }

func (p processRepository) BindingIdentity() string { return p.RootPath() }

type processRuntime struct {
	resolver          internaladversary.Resolver
	stdin             io.Reader
	tempDir, homeDir  string
	environment       internaladversary.ProcessEnvironment
	resolveExecutable func(string) (string, error)
	launcher          internaladversary.ProcessLauncher
	timer             func(time.Duration) internaladversary.RuntimeTimer
	git               internaladversary.GitDiffer
	now               func() time.Time
	node              internaladversary.NodeResolver
	files             internaladversary.RuntimeFiles
	dataRoot          string
	buildStateDir     string
	buildProject      func(context.Context, pack.BuildOptions) error
}

func (p processRuntime) BindingIdentity() string { return p.resolver.Repository.RootPath() }
func (p processRuntime) Run(ctx context.Context, opts application.AdversaryRunOptions) error {
	r := p.runner(opts)
	return r.Run(ctx, toInternalRunOptions(opts))
}
func (p processRuntime) Inspect(ctx context.Context, opts application.AdversaryRunOptions) error {
	r := p.runner(opts)
	return r.Inspect(toInternalRunOptions(opts))
}
func (p processRuntime) runner(opts application.AdversaryRunOptions) internaladversary.Runner {
	shell := func() ([]string, error) { return internaladversary.PlatformShell(p.node.LookPath) }
	return internaladversary.Runner{Stdout: opts.Stdout, Stderr: opts.Stderr, Stdin: p.stdin, Git: p.git, TempDir: p.tempDir, HomeDir: p.homeDir, DataRoot: p.dataRoot, BuildStateDir: p.buildStateDir, Now: p.now, Files: p.files, BuildProject: p.buildProject, Shell: shell, Executor: internaladversary.HostExecutor{Stdout: opts.Stderr, Stderr: opts.Stderr, Stdin: p.stdin, Environment: p.environment, ResolveExecutable: p.resolveExecutable, FindNode: p.node.Find, Shell: shell, Launcher: p.launcher, Timer: p.timer}, HostExecution: true, Repository: &p.resolver.Repository, Resolver: &p.resolver, RequireInjectedResolver: true}
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
	client := adversarylabs.NewClientWithBaseURL(f.store, base)
	if f.http != nil { // explicit test/integration injection only
		client.HTTP = f.http
	}
	return classifiedAPIClient{inner: client}
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
func (r processOCIRegistry) PushSources(ctx context.Context, ref oci.Reference, manifest []byte, blobs []oci.SourceBlob) (string, error) {
	v, e := r.HTTPRegistry.PushSources(ctx, ref, manifest, blobs)
	return v, networkError("OCI push", e)
}
func (r processOCIRegistry) PushAdversaryManifestReferrer(ctx context.Context, ref oci.Reference, digest string, manifest []byte) (string, string, error) {
	a, b, e := r.HTTPRegistry.PushAdversaryManifestReferrer(ctx, ref, digest, manifest)
	return a, b, networkError("OCI referrer push", e)
}
func (r processOCIRegistry) PullSources(ctx context.Context, ref oci.Reference) (*oci.PulledSources, error) {
	v, e := r.HTTPRegistry.PullSources(ctx, ref)
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
	docker                 oci.CredentialStore
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
	environment := internaladversary.NewProcessEnvironment(os.Environ(), runtime.GOOS == "windows")
	resolver, err := internaladversary.DefaultResolver()
	if err != nil {
		return nil, err
	}
	store, err := adversarylabs.DefaultConfigStore()
	if err != nil {
		return nil, err
	}
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("resolve home directory: %w", err)
	}
	buildStateDir, err := pack.ResolveBuildStateDir("")
	if err != nil {
		return nil, fmt.Errorf("resolve build state directory: %w", err)
	}
	apiURL := snapshotEnvDefault(environment, "ADVERSARY_API_URL", adversarylabs.DefaultAPIURL)
	host := snapshotEnvDefault(environment, "ADVERSARY_REGISTRY_HOST", adversarylabs.DefaultRegistry)
	namespace := snapshotEnvDefault(environment, "ADVERSARY_REGISTRY_NAMESPACE", "")
	resolver.Repository.DefaultRegistry = host
	resolver.Repository.DefaultNamespace = namespace
	var debug io.Writer
	if value, ok := environment.Lookup("ADVERSARY_OCI_DEBUG"); ok && strings.TrimSpace(value) != "" {
		debug = stderr
	}
	files := internaladversary.OSRuntimeFiles{}
	pathext, _ := environment.Lookup("PATHEXT")
	resolveExplicitExecutable, resolvePATHExecutable := executableResolvers(files, pathext)
	lookPath := func(file string) (string, error) { return environment.LookPath(file, resolvePATHExecutable) }
	npm, npmErr := capturedNPM(homeDir, lookPath, files, resolveExplicitExecutable)
	nodePath, nodeErr := capturedNode(npm, lookPath, files, resolveExplicitExecutable)
	dockerPath, dockerErr := lookPath("docker")
	buildEnvironment := pack.BuildEnvironment{NPM: npm, NPMError: npmErr, Node: nodePath, NodeError: nodeErr, Docker: dockerPath, DockerError: dockerErr, Environment: environment.Entries(nil), Run: func(ctx context.Context, executable string, args []string, dir string, env []string, stdout, stderr io.Writer, capture bool) ([]byte, error) {
		cmd := exec.CommandContext(ctx, executable, args...)
		cmd.WaitDelay = 2 * time.Second
		cmd.Dir, cmd.Env, cmd.Stdout, cmd.Stderr = dir, env, stdout, stderr
		if !capture {
			err := cmd.Run()
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			return nil, err
		}
		return runCapturedProcess(ctx, cmd, 1<<20, "build probe")
	}}
	docker := oci.DockerCredentialStore{HomeDir: homeDir, Lstat: os.Lstat, Open: oci.OpenRegularNoFollow, RunHelper: newCredentialHelperRunner(environment, lookPath)}
	authStore := processAuthStore{store}
	apiFactory := processAPIFactory{store: store}
	registryFactory := processRegistryFactory{store: authStore, docker: docker, host: host, namespace: namespace, debug: debug, identity: store.Path}
	output := internaladversary.ExecProcessOutputRunner{}
	node := internaladversary.NodeResolver{LookupEnv: environment.Lookup, LookPath: lookPath, HomeDir: homeDir, Glob: files.Glob, ResolveExecutable: resolveExplicitExecutable, Environment: environment, Output: output}
	gitPath, gitErr := lookPath("git")
	git := internaladversary.CommandGitDiffer{Executable: gitPath, Environment: environment, Output: output, ResolutionError: gitErr}
	buildProject := composedBuildProject(buildEnvironment, buildStateDir)
	process := processRuntime{resolver: resolver, stdin: stdin, tempDir: internalpaths.TempDir(), homeDir: homeDir, dataRoot: applicationDataRoot(resolver.Repository.Root), buildStateDir: buildStateDir, environment: environment, resolveExecutable: func(name string) (string, error) {
		if filepath.IsAbs(name) {
			return resolveExplicitExecutable(name)
		}
		return lookPath(name)
	}, launcher: internaladversary.ExecProcessLauncher{}, timer: internaladversary.NewRuntimeTimer, git: git, now: time.Now, node: node, files: files, buildProject: buildProject}
	references := processReferences{registry: host, namespace: namespace}
	browserAuth := dependencies.BrowserAuth{Entropy: rand.Reader, ListenFunc: net.Listen, NewServerFunc: dependencies.NewHTTPCallbackServer, OpenFunc: func(ctx context.Context, u string) error { return openBrowser(ctx, u, environment, lookPath, output) }}
	return application.New(application.Dependencies{Stdin: stdin, Stdout: stdout, Stderr: stderr, Clock: newSystemClock(), Projects: processProjects{references: references, build: buildEnvironment, buildStateDir: buildStateDir}, References: references, Auth: authStore, API: apiFactory, Registries: registryFactory, DefaultAPIURL: apiURL, RegistryHost: host, RegistryNS: namespace, Repository: processRepository{resolver.Repository}, Resolver: processResolver{resolver: resolver}, Runtime: process, BrowserAuth: browserAuth, TTY: processTTY{}})
}

func capturedNPM(home string, lookPath func(string) (string, error), files internaladversary.RuntimeFiles, resolveExplicit func(string) (string, error)) (string, error) {
	if path, err := lookPath("npm"); err == nil {
		return path, nil
	}
	candidates := []string{filepath.Join(home, ".volta", "bin", "npm"), filepath.Join(home, ".asdf", "shims", "npm")}
	nvm, _ := files.Glob(filepath.Join(home, ".nvm", "versions", "node", "*", "bin", "npm"))
	sort.Sort(sort.Reverse(sort.StringSlice(nvm)))
	candidates = append(nvm, candidates...)
	for _, candidate := range candidates {
		info, err := files.Stat(candidate)
		if err != nil || info.IsDir() {
			continue
		}
		if resolved, err := resolveExplicit(candidate); err == nil {
			return resolved, nil
		}
	}
	return "", fmt.Errorf("npm was not found in captured PATH or home")
}

func capturedNode(npm string, lookPath func(string) (string, error), files internaladversary.RuntimeFiles, resolveExplicit func(string) (string, error)) (string, error) {
	if npm != "" {
		adjacent := filepath.Join(filepath.Dir(npm), "node")
		if info, err := files.Stat(adjacent); err == nil && !info.IsDir() {
			if resolved, err := resolveExplicit(adjacent); err == nil {
				return resolved, nil
			}
		}
	}
	return lookPath("node")
}

var errCapturedOutputLimit = errors.New("captured process output limit exceeded")

type boundedCapture struct {
	buffer    bytes.Buffer
	remaining int
	exceeded  bool
	kill      func()
}

func (w *boundedCapture) Write(data []byte) (int, error) {
	if len(data) <= w.remaining {
		w.remaining -= len(data)
		return w.buffer.Write(data)
	}
	w.exceeded = true
	if w.kill != nil {
		w.kill()
	}
	written := 0
	if w.remaining > 0 {
		written, _ = w.buffer.Write(data[:w.remaining])
		w.remaining = 0
	}
	return written, errCapturedOutputLimit
}

func runCapturedProcess(ctx context.Context, cmd *exec.Cmd, limit int, label string) ([]byte, error) {
	captured := &boundedCapture{remaining: limit, kill: func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}}
	cmd.Stdout = captured
	err := cmd.Run()
	if captured.exceeded || errors.Is(err, errCapturedOutputLimit) {
		return nil, fmt.Errorf("%s output exceeds %d bytes", label, limit)
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	return captured.buffer.Bytes(), err
}

func newCredentialHelperRunner(environment internaladversary.ProcessEnvironment, lookPath func(string) (string, error)) func(context.Context, string, string) ([]byte, error) {
	return func(ctx context.Context, executable, input string) ([]byte, error) {
		resolved, err := lookPath(executable)
		if err != nil {
			return nil, err
		}
		cmd := exec.CommandContext(ctx, resolved, "get")
		cmd.WaitDelay = 2 * time.Second
		cmd.Stdin = strings.NewReader(input)
		cmd.Env = environment.Entries(nil)
		return runCapturedProcess(ctx, cmd, 1<<20, "credential helper")
	}
}

func executableResolvers(files internaladversary.RuntimeFiles, pathext string) (strict, fromPATH func(string) (string, error)) {
	validate := func(path string) error { return internaladversary.ValidateExecutable(path, pathext) }
	canonicalize := func(path string) (string, error) {
		if !filepath.IsAbs(path) {
			return "", fmt.Errorf("executable path %q is not absolute", path)
		}
		path = filepath.Clean(path)
		canonical, err := files.EvalSymlinks(path)
		if err != nil {
			return "", err
		}
		if !filepath.IsAbs(canonical) {
			return "", fmt.Errorf("canonical executable path %q is not absolute", canonical)
		}
		return filepath.Clean(canonical), nil
	}
	strict = func(path string) (string, error) {
		if !filepath.IsAbs(path) {
			return "", fmt.Errorf("executable path %q is not absolute", path)
		}
		path = filepath.Clean(path)
		if err := validate(path); err != nil {
			return "", err
		}
		return canonicalize(path)
	}
	fromPATH = func(path string) (string, error) {
		canonical, err := canonicalize(path)
		if err != nil {
			return "", err
		}
		if err := validate(canonical); err != nil {
			return "", err
		}
		return canonical, nil
	}
	return strict, fromPATH
}

func applicationDataRoot(repositoryRoot string) string { return filepath.Dir(repositoryRoot) }

func snapshotEnvDefault(environment internaladversary.ProcessEnvironment, key, fallback string) string {
	if value, ok := environment.Lookup(key); ok && strings.TrimSpace(value) != "" {
		return strings.TrimRight(strings.TrimSpace(value), "/")
	}
	return strings.TrimRight(fallback, "/")
}

func openBrowser(ctx context.Context, url string, environment internaladversary.ProcessEnvironment, lookPath func(string) (string, error), output internaladversary.ProcessOutputRunner) error {
	var name string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		name, args = "open", []string{url}
	case "windows":
		name, args = "rundll32", []string{"url.dll,FileProtocolHandler", url}
	default:
		name, args = "xdg-open", []string{url}
	}
	executable, err := lookPath(name)
	if err != nil {
		return fmt.Errorf("resolve browser launcher: %w", err)
	}
	_, stderr, err := output.RunOutput(ctx, internaladversary.ProcessOutputOptions{Path: executable, Args: args, Env: environment.Entries(nil)})
	if err != nil {
		if detail := strings.TrimSpace(string(stderr)); detail != "" {
			return fmt.Errorf("open browser: %s", detail)
		}
		return fmt.Errorf("open browser: %w", err)
	}
	return nil
}
