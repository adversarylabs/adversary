package application

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/adversarylabs/adversary/pkg/oci"
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

type fakeRegistry struct{}

func (fakeRegistry) Push(context.Context, oci.Reference, []byte, []oci.Blob) (string, error) {
	return "", nil
}
func (fakeRegistry) Pull(context.Context, oci.Reference) (oci.PulledArtifact, error) {
	return oci.PulledArtifact{}, nil
}
func (fakeRegistry) Resolve(context.Context, oci.Reference) (string, error) { return "", nil }

type fakeRepo struct{}

func (fakeRepo) Resolve(string) (repository.Record, error) { return repository.Record{}, nil }
func (fakeRepo) PlanGC() (repository.GCPlan, error)        { return repository.GCPlan{}, nil }
func (fakeRepo) ApplyGC(repository.GCPlan, bool) (repository.GCReport, error) {
	return repository.GCReport{}, nil
}
func (fakeRepo) CheckAll() (repository.CheckReport, error) { return repository.CheckReport{}, nil }
func (fakeRepo) RepairAll(map[string][]byte) (repository.RepairReport, error) {
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

func (fakeResolver) Resolve(context.Context, string) (Resolution, error) { return Resolution{}, nil }

type fakeRuntime struct{}

func (fakeRuntime) Run(context.Context, []string, RunOptions) error { return nil }

type fakeBrowser struct{}

func (fakeBrowser) Open(context.Context, string) error { return nil }

type fakeTTY struct{}

func (fakeTTY) Interactive(io.Reader) bool                                       { return false }
func (fakeTTY) ReadSecret(context.Context, io.Reader, io.Writer) ([]byte, error) { return nil, nil }

func TestFullyPopulatedDependencyGraphIsConstructible(t *testing.T) {
	b := &bytes.Buffer{}
	app, err := New(Dependencies{Stdin: b, Stdout: b, Stderr: b, Clock: fakeClock{}, Env: fakeEnv{}, Config: fakeConfig{}, Paths: fakePaths{}, HTTP: fakeHTTP{}, Credentials: fakeCreds{}, Registry: fakeRegistry{}, Repository: fakeRepo{}, Resolver: fakeResolver{}, Runtime: fakeRuntime{}, Browser: fakeBrowser{}, TTY: fakeTTY{}})
	if err != nil || app == nil {
		t.Fatalf("app=%v err=%v", app, err)
	}
}
