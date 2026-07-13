package application

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/adversarylabs/adversary/pkg/adversarylabs"
	"github.com/adversarylabs/adversary/pkg/blobsource"
	"github.com/adversarylabs/adversary/pkg/oci"
	"github.com/adversarylabs/adversary/pkg/pack"
	"github.com/adversarylabs/adversary/pkg/repository"
)

func TestNewReportsTypedMissingDependencies(t *testing.T) {
	_, err := New(Dependencies{Stdin: &bytes.Buffer{}, Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
	if err == nil || !IsKind(err, "missing-dependency") {
		t.Fatalf("error=%v", err)
	}
}

type fakeClock struct{}

func (fakeClock) Now() time.Time               { return time.Unix(1, 0) }
func (fakeClock) NewTimer(time.Duration) Timer { return fakeTimer{make(chan time.Time)} }

type fakeTimer struct{ ch chan time.Time }

func (f fakeTimer) C() <-chan time.Time { return f.ch }
func (fakeTimer) Stop() bool            { return true }

type fakeEnv struct{}

func (fakeEnv) Lookup(string) (string, bool) { return "", false }

type fakeConfig struct{}

func (fakeConfig) Get(context.Context, string) (string, error) { return "", nil }
func (fakeConfig) Set(context.Context, string, string) error   { return nil }

type fakePaths struct{}

func (fakePaths) DataDir() (string, error)   { return "/data", nil }
func (fakePaths) ConfigDir() (string, error) { return "/config", nil }
func (fakePaths) TempDir() string            { return "/tmp" }

type fakeHTTP struct{}

func (fakeHTTP) Do(*http.Request) (*http.Response, error) { return nil, nil }

type fakeCreds struct{}

func (fakeCreds) Credentials(string) (oci.Credentials, bool) { return oci.Credentials{}, false }

type fakeProjects struct{}

func (fakeProjects) Init(ProjectInitOptions) (ProjectInitResult, error) {
	return ProjectInitResult{}, nil
}
func (fakeProjects) RenderInit(io.Writer, ProjectInitResult, string) {}
func (fakeProjects) Validate(context.Context, string, Resolver) (ProjectValidation, error) {
	return ProjectValidation{}, nil
}
func (fakeProjects) Check(pack.Options) (pack.Preflight, error) { return pack.Preflight{}, nil }
func (fakeProjects) Pack(context.Context, pack.Options) (pack.Artifact, error) {
	return pack.Artifact{}, nil
}

type fakeReferences struct{}

func (fakeReferences) Parse(string) (oci.Reference, error) { return oci.Reference{}, nil }

type fakeRegistry struct{}

func (fakeRegistry) PushSources(context.Context, oci.Reference, []byte, []oci.SourceBlob) (string, error) {
	return "", nil
}
func (fakeRegistry) PullSources(context.Context, oci.Reference) (*oci.PulledSources, error) {
	return &oci.PulledSources{}, nil
}
func (fakeRegistry) Resolve(context.Context, oci.Reference) (string, error) { return "", nil }

type fakeAuth struct{}

func (fakeAuth) BindingIdentity() string { return "test" }

func (fakeAuth) ExactAuthE(string) (adversarylabs.Auth, bool, error) {
	return adversarylabs.Auth{}, false, nil
}
func (fakeAuth) SetAuth(string, adversarylabs.Auth) error       { return nil }
func (fakeAuth) RemoveAuthCAS(string, adversarylabs.Auth) error { return nil }

type fakeAPI struct{}

func (fakeAPI) BindingIdentity() string { return "test" }

func (fakeAPI) New(string) APIClient { return adversarylabs.Client{} }

type fakeOCIRegistry struct{ fakeRegistry }

func (fakeOCIRegistry) PushAdversaryManifestReferrer(context.Context, oci.Reference, string, []byte) (string, string, error) {
	return "", "", nil
}
func (fakeOCIRegistry) SetPlainHTTP(bool) {}

type fakeRegistryFactory struct{}

func (fakeRegistryFactory) BindingIdentity() string { return "test" }

func (fakeRegistryFactory) New(string, string) (OCIRegistry, error) { return fakeOCIRegistry{}, nil }

type fakeRepo struct{}

func (fakeRepo) BindingIdentity() string                   { return "artifacts" }
func (fakeRepo) Resolve(string) (repository.Record, error) { return repository.Record{}, nil }
func (fakeRepo) PlanGC() (repository.GCPlan, error)        { return repository.GCPlan{}, nil }
func (fakeRepo) ApplyGC(repository.GCPlan, bool) (repository.GCReport, error) {
	return repository.GCReport{}, nil
}

type mismatchedAPI struct{ fakeAPI }

func (mismatchedAPI) BindingIdentity() string { return "other" }

func TestDependencyBindingMismatchFailsClosed(t *testing.T) {
	b := &bytes.Buffer{}
	_, err := New(Dependencies{Stdin: b, Stdout: b, Stderr: b, Clock: fakeClock{}, Projects: fakeProjects{}, References: fakeReferences{}, Auth: fakeAuth{}, API: mismatchedAPI{}, Registries: fakeRegistryFactory{}, DefaultAPIURL: "https://api.test", RegistryHost: "registry.test", Repository: fakeRepo{}, Resolver: fakeResolver{}, Runtime: fakeRuntime{}, Browser: fakeBrowser{}, TTY: fakeTTY{}})
	if err == nil || !IsKind(err, "invalid-dependency") {
		t.Fatalf("error=%v", err)
	}
}
func (fakeRepo) CheckAll() (repository.CheckReport, error) { return repository.CheckReport{}, nil }
func (fakeRepo) RepairAll(map[string]blobsource.Source) (repository.RepairReport, error) {
	return repository.RepairReport{}, nil
}
func (fakeRepo) DeleteRef(string, string) error { return nil }
func (fakeRepo) MigrationStatus(string) (repository.MigrationStatus, error) {
	return repository.MigrationStatus{}, nil
}
func (fakeRepo) LeaseMaterialized(repository.Record) (*repository.MaterializationLease, error) {
	return nil, nil
}

type fakeResolver struct{}

func (fakeResolver) BindingIdentity() string                             { return "artifacts" }
func (fakeResolver) Resolve(context.Context, string) (Resolution, error) { return Resolution{}, nil }
func (fakeResolver) Lookup(context.Context, string) (Resolution, error)  { return Resolution{}, nil }
func (fakeResolver) ResolveRecord(string) (repository.Record, error)     { return repository.Record{}, nil }
func (fakeResolver) HasExact(string) (bool, error)                       { return false, nil }
func (fakeResolver) Entries(int) ([]repository.Entry, error)             { return nil, nil }
func (fakeResolver) CanonicalReferenceFor(string, string) (string, error) {
	return "registry.test/library/example:1", nil
}
func (fakeResolver) Inventory(repository.Record) ([]pack.File, error) { return nil, nil }
func (fakeResolver) PayloadSources(repository.Record) (*repository.PayloadLease, error) {
	return nil, nil
}
func (fakeResolver) ImportPacked(pack.Artifact, string) (repository.Record, error) {
	return repository.Record{}, nil
}
func (fakeResolver) ImportSources(repository.SourceImport) (repository.Record, error) {
	return repository.Record{}, nil
}
func (fakeResolver) CommitEquivalentManifest(string, string, []byte) (repository.Record, error) {
	return repository.Record{}, nil
}
func (fakeResolver) UpdateRef(string, string, string) error { return nil }

type fakeRuntime struct{}

func (fakeRuntime) BindingIdentity() string                            { return "artifacts" }
func (fakeRuntime) Run(context.Context, AdversaryRunOptions) error     { return nil }
func (fakeRuntime) Inspect(context.Context, AdversaryRunOptions) error { return nil }

type mismatchedResolver struct{ fakeResolver }

func (mismatchedResolver) BindingIdentity() string { return "other-artifacts" }

func TestArtifactBindingMismatchFailsClosed(t *testing.T) {
	b := &bytes.Buffer{}
	_, err := New(Dependencies{Stdin: b, Stdout: b, Stderr: b, Clock: fakeClock{}, Projects: fakeProjects{}, References: fakeReferences{}, Auth: fakeAuth{}, API: fakeAPI{}, Registries: fakeRegistryFactory{}, DefaultAPIURL: "https://api.test", RegistryHost: "registry.test", Repository: fakeRepo{}, Resolver: mismatchedResolver{}, Runtime: fakeRuntime{}, Browser: fakeBrowser{}, TTY: fakeTTY{}})
	if err == nil || !IsKind(err, "invalid-dependency") {
		t.Fatalf("error=%v", err)
	}
}

type fakeBrowser struct{}

func (fakeBrowser) Open(context.Context, string) error { return nil }

type fakeTTY struct{}

func (fakeTTY) Interactive(io.Reader) bool                                       { return false }
func (fakeTTY) ReadSecret(context.Context, io.Reader, io.Writer) ([]byte, error) { return nil, nil }

func TestFullyPopulatedDependencyGraphIsConstructible(t *testing.T) {
	b := &bytes.Buffer{}
	app, err := New(Dependencies{Stdin: b, Stdout: b, Stderr: b, Clock: fakeClock{}, Projects: fakeProjects{}, References: fakeReferences{}, Auth: fakeAuth{}, API: fakeAPI{}, Registries: fakeRegistryFactory{}, DefaultAPIURL: "https://api.test", RegistryHost: "registry.test", Repository: fakeRepo{}, Resolver: fakeResolver{}, Runtime: fakeRuntime{}, Browser: fakeBrowser{}, TTY: fakeTTY{}})
	if err != nil || app == nil {
		t.Fatalf("app=%v err=%v", app, err)
	}
}
