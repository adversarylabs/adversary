package adversary

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adversarylabs/adversary/pkg/oci"
	"github.com/adversarylabs/adversary/pkg/repository"
)

type policyExecutor struct {
	backend   ExecutorBackend
	caps      ExecutorCapabilities
	called    int
	spec      RuntimeSpec
	beforeRun func(RuntimeSpec) error
}

func (e *policyExecutor) Backend() ExecutorBackend           { return e.backend }
func (e *policyExecutor) Capabilities() ExecutorCapabilities { return e.caps }
func (e *policyExecutor) Run(_ context.Context, spec RuntimeSpec) (RuntimeResult, error) {
	e.called++
	e.spec = spec
	if e.beforeRun != nil {
		if err := e.beforeRun(spec); err != nil {
			return RuntimeResult{}, err
		}
	}
	if err := os.WriteFile(filepath.Join(spec.RunDir, "output.json"), minimalEnvelope(), 0o600); err != nil {
		return RuntimeResult{}, err
	}
	return RuntimeResult{ExitCode: 0, Kind: "Process"}, nil
}

func TestLocalSourceExecutesWithHostExecutorWithoutWarning(t *testing.T) {
	project := writeRunnerProject(t, "")
	writeFile(t, filepath.Join(project, "index.js"), "")
	executor := &policyExecutor{backend: HostExecutorBackend}
	var stderr bytes.Buffer
	err := Runner{Stdout: &bytes.Buffer{}, Stderr: &stderr, Executor: executor}.Run(context.Background(), RunOptions{
		AdversaryRef: project, RepoPath: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if executor.called != 1 || executor.spec.Digest != "" || executor.spec.Publisher != "local" {
		t.Fatalf("executor call=%d spec=%+v", executor.called, executor.spec)
	}
	if strings.Contains(strings.ToLower(stderr.String()), "warning") {
		t.Fatalf("local execution emitted warning: %q", stderr.String())
	}
}

func TestTrustedRemoteExecutesWithHostExecutorAndReportsIdentity(t *testing.T) {
	repo, resolver, record := importPolicyArtifact(t, "adversarylabs/dockerfile:1.2.0")
	executor := &policyExecutor{backend: HostExecutorBackend}
	var stderr bytes.Buffer
	err := Runner{Stdout: &bytes.Buffer{}, Stderr: &stderr, Executor: executor, Repository: &repo, Resolver: &resolver}.Run(context.Background(), RunOptions{
		AdversaryRef: "adversarylabs/dockerfile:1.2.0", RepoPath: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if executor.called != 1 || executor.spec.Digest != record.Digest || executor.spec.Publisher != "adversarylabs" {
		t.Fatalf("executor call=%d spec=%+v digest=%s", executor.called, executor.spec, record.Digest)
	}
	for _, want := range []string{"Publisher: adversarylabs", "Digest: " + record.Digest, "Execution backend: HostExecutor"} {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("identity output missing %q: %q", want, stderr.String())
		}
	}
	if strings.Contains(stderr.String(), "WARNING") {
		t.Fatalf("trusted publisher emitted warning: %q", stderr.String())
	}
}

func TestUnknownRemoteRequiresSandboxOrUnsafeHostOverride(t *testing.T) {
	repo, resolver, record := importPolicyArtifact(t, "randomperson/dockerfile:1.2.0")
	host := &policyExecutor{backend: HostExecutorBackend}
	err := Runner{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}, Executor: host, Repository: &repo, Resolver: &resolver}.Run(context.Background(), RunOptions{
		AdversaryRef: "randomperson/dockerfile:1.2.0", RepoPath: t.TempDir(),
	})
	if err == nil || !strings.Contains(err.Error(), "--allow-unsafe-host-execution") || host.called != 0 {
		t.Fatalf("error=%v calls=%d", err, host.called)
	}

	var warning bytes.Buffer
	err = Runner{Stdout: &bytes.Buffer{}, Stderr: &warning, Executor: host, Repository: &repo, Resolver: &resolver}.Run(context.Background(), RunOptions{
		AdversaryRef: "randomperson/dockerfile:1.2.0", RepoPath: t.TempDir(), AllowUnsafeHostExecution: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if host.called != 1 || host.spec.Digest != record.Digest {
		t.Fatalf("calls=%d spec=%+v", host.called, host.spec)
	}
	if !strings.Contains(warning.String(), "WARNING: unknown publisher") || !strings.Contains(warning.String(), record.Digest) {
		t.Fatalf("unsafe override warning=%q", warning.String())
	}

	sandbox := &policyExecutor{backend: NativeSandboxExecutorBackend, caps: allTestExecutorCapabilities()}
	err = Runner{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}, Executor: sandbox, Repository: &repo, Resolver: &resolver}.Run(context.Background(), RunOptions{
		AdversaryRef: "randomperson/dockerfile:1.2.0", RepoPath: t.TempDir(),
	})
	if err != nil || sandbox.called != 1 {
		t.Fatalf("sandbox error=%v calls=%d", err, sandbox.called)
	}
}

func TestMutableRemoteReferenceIsPinnedBeforeExecution(t *testing.T) {
	repo, resolver, original := importPolicyArtifact(t, "adversarylabs/dockerfile:1.2.0")
	replacement, err := repo.ImportPacked(resolverArtifact(t, t.TempDir(), "adversarylabs/dockerfile", "2.0.0"), "adversarylabs/dockerfile:2.0.0")
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := repo.CanonicalReferenceFor(original.Digest, "adversarylabs/dockerfile:1.2.0")
	if err != nil {
		t.Fatal(err)
	}
	executor := &policyExecutor{backend: HostExecutorBackend, beforeRun: func(spec RuntimeSpec) error {
		return repo.UpdateRef(canonical, original.Digest, replacement.Digest)
	}}
	var stderr bytes.Buffer
	err = Runner{Stdout: &bytes.Buffer{}, Stderr: &stderr, Executor: executor, Repository: &repo, Resolver: &resolver}.Run(context.Background(), RunOptions{
		AdversaryRef: "adversarylabs/dockerfile:1.2.0", RepoPath: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if executor.spec.Digest != original.Digest || !strings.Contains(stderr.String(), "Digest: "+original.Digest) {
		t.Fatalf("executed=%s output=%q want original=%s", executor.spec.Digest, stderr.String(), original.Digest)
	}
	current, err := repo.Resolve(canonical)
	if err != nil || current.Digest != replacement.Digest {
		t.Fatalf("mutable reference was not changed during launch: record=%+v error=%v", current, err)
	}
}

func TestRequestedPermissionsAreComparedWithExecutorCapabilities(t *testing.T) {
	requested := RequestedPermissions{FilesystemReadIsolation: true, FilesystemWriteIsolation: true, EnvironmentIsolation: true, NetworkIsolation: true}
	if err := validateExecutorCapabilities(requested, ExecutorCapabilities{}, HostExecutorBackend); err == nil || !strings.Contains(err.Error(), "filesystem.read") {
		t.Fatalf("host capability error=%v", err)
	}
	if err := validateExecutorCapabilities(requested, allTestExecutorCapabilities(), NativeSandboxExecutorBackend); err != nil {
		t.Fatalf("sandbox capabilities rejected: %v", err)
	}
}

func TestManifestPermissionsReachCapableExecutor(t *testing.T) {
	project := writeRunnerProject(t, "permissions:\n  filesystem:\n    read: [.]\n    write: [.adversary/results]\n  network: false\n  environment:\n    allow: [CI]\n")
	executor := &policyExecutor{backend: NativeSandboxExecutorBackend, caps: allTestExecutorCapabilities()}
	if err := (Runner{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}, Executor: executor}).Run(context.Background(), RunOptions{
		AdversaryRef: project, RepoPath: t.TempDir(),
	}); err != nil {
		t.Fatal(err)
	}
	permissions := executor.spec.Permissions
	if !permissions.NetworkNone || len(permissions.FilesystemRead) != 1 || permissions.FilesystemRead[0] != "." ||
		len(permissions.FilesystemWrite) != 1 || permissions.FilesystemWrite[0] != ".adversary/results" ||
		len(permissions.EnvironmentAllow) != 1 || permissions.EnvironmentAllow[0] != "CI" {
		t.Fatalf("runtime permissions=%+v", permissions)
	}
}

func TestAdvisoryManifestPermissionsDoNotBlockLocalHostExecution(t *testing.T) {
	project := writeRunnerProject(t, "permissions:\n  filesystem:\n    read: [.]\n  network: false\n")
	writeFile(t, filepath.Join(project, "index.js"), "")
	executor := &policyExecutor{backend: HostExecutorBackend}
	if err := (Runner{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}, Executor: executor}).Run(context.Background(), RunOptions{
		AdversaryRef: project, RepoPath: t.TempDir(),
	}); err != nil {
		t.Fatal(err)
	}
	if executor.called != 1 || !executor.spec.Permissions.NetworkNone || len(executor.spec.Permissions.FilesystemRead) != 1 {
		t.Fatalf("executor call=%d permissions=%+v", executor.called, executor.spec.Permissions)
	}
	if executor.spec.Permissions.Required != (RequestedPermissions{}) {
		t.Fatalf("advisory permissions became required: %+v", executor.spec.Permissions.Required)
	}
}

func TestRequestedPermissionsAreComparedWithAllowedPolicy(t *testing.T) {
	request := ExecutionPolicyRequest{
		Trust:        TrustDecision{Publisher: PublisherIdentity{Name: "adversarylabs"}, Trust: TrustedPublisherTrust},
		Requested:    RequestedPermissions{NetworkIsolation: true},
		Allowed:      AllowedPermissions{},
		Backend:      NativeSandboxExecutorBackend,
		Capabilities: allTestExecutorCapabilities(),
	}
	if _, err := DecideExecutionPolicy(request); err == nil || !strings.Contains(err.Error(), "does not allow requested network.none") {
		t.Fatalf("permission policy error=%v", err)
	}
}

func TestDefaultPublisherTrustPolicy(t *testing.T) {
	policy := DefaultPublisherTrustPolicy()
	for publisher, want := range map[string]PublisherTrust{
		"adversarylabs": TrustedPublisherTrust,
		"replicated":    UnknownPublisherTrust,
		"randomperson":  UnknownPublisherTrust,
	} {
		if got := policy.Evaluate(PublisherIdentity{Name: publisher, Registry: oci.DefaultRegistry}).Trust; got != want {
			t.Errorf("publisher %q trust=%q want=%q", publisher, got, want)
		}
	}
	if got := policy.Evaluate(PublisherIdentity{Name: "adversarylabs", Registry: "evil.example"}).Trust; got != UnknownPublisherTrust {
		t.Fatalf("lookalike registry trust=%q", got)
	}
	if got := policy.Evaluate(PublisherIdentity{Name: "anything", Local: true}).Trust; got != LocalSourceTrust {
		t.Fatalf("local trust=%q", got)
	}
}

func TestHostExecutorReportsCapabilities(t *testing.T) {
	host := HostExecutor{}
	if host.Backend() != HostExecutorBackend {
		t.Fatalf("backend=%q", host.Backend())
	}
	if host.Capabilities() != (ExecutorCapabilities{}) {
		t.Fatalf("host capabilities=%+v", host.Capabilities())
	}
}

func importPolicyArtifact(t *testing.T, reference string) (repository.Repository, Resolver, repository.Record) {
	t.Helper()
	repo := repository.Repository{Root: t.TempDir()}
	t.Cleanup(func() { makeResolverWritable(repo.Root) })
	record, err := repo.ImportPacked(resolverArtifact(t, t.TempDir(), strings.Split(reference, ":")[0], "1.2.0"), reference)
	if err != nil {
		t.Fatal(err)
	}
	return repo, Resolver{Repository: repo}, record
}
