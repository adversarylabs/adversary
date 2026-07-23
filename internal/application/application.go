// Package application defines the explicit application boundary constructed at
// the process edge and injected into every effectful command.
package application

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/adversarylabs/adversary/pkg/adversarylabs"
	"github.com/adversarylabs/adversary/pkg/blobsource"
	"github.com/adversarylabs/adversary/pkg/detection"
	"github.com/adversarylabs/adversary/pkg/oci"
	"github.com/adversarylabs/adversary/pkg/pack"
	"github.com/adversarylabs/adversary/pkg/repository"
)

type Clock interface {
	Now() time.Time
	NewTimer(time.Duration) Timer
}
type Timer interface {
	C() <-chan time.Time
	Stop() bool
}

// Environment and HTTPClient are adapter contracts used by concrete process
// composition; they are deliberately not App dependencies.
type Environment interface{ Lookup(string) (string, bool) }
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

// Projects owns filesystem and build operations for project-facing commands.
// Keeping these operations behind one port makes command handlers hermetic.
type Projects interface {
	Init(ProjectInitOptions) (ProjectInitResult, error)
	RenderInit(io.Writer, ProjectInitResult, string)
	Validate(context.Context, string, Resolver) (ProjectValidation, error)
	Check(pack.Options) (pack.Preflight, error)
	Pack(context.Context, pack.Options) (pack.Artifact, error)
}

const DefaultProjectSDK = "typescript"

type ProjectInitOptions struct{ Destination, SDK string }
type ProjectInitResult struct{ Location, SDK string }
type ProjectValidation struct {
	Path, Name, Runtime string
}
type ProjectError struct {
	Code, Path string
	Err        error
}

func (e *ProjectError) Error() string { return e.Err.Error() }
func (e *ProjectError) Unwrap() error { return e.Err }

// References parses references with defaults captured during App construction.
type References interface {
	Parse(string) (oci.Reference, error)
}

// AuthStore is the scoped credential persistence required by CLI handlers.
type AuthStore interface {
	ExactAuthE(string) (adversarylabs.Auth, bool, error)
	SetAuth(string, adversarylabs.Auth) error
	RemoveAuthCAS(string, adversarylabs.Auth) error
}

// APIClient contains exactly the Adversary Labs operations used by the CLI.
type APIClient interface {
	BeginLogin(context.Context, adversarylabs.LoginOptions) (adversarylabs.DeviceLogin, error)
	LoginWithPassword(context.Context, adversarylabs.PasswordLoginOptions) (adversarylabs.TokenResponse, error)
	BrowserLoginURL(adversarylabs.BrowserLoginOptions) (string, error)
	ExchangeCode(context.Context, string, string, string) (adversarylabs.TokenResponse, error)
	PollToken(context.Context, string) (adversarylabs.TokenResponse, error)
	Revoke(context.Context, string) error
	Search(context.Context, string, string) ([]adversarylabs.SearchResult, error)
	Whoami(context.Context, string) (adversarylabs.WhoamiResponse, error)
	RecordPull(ctx context.Context, token, reference, digest string) error
}
type APIFactory interface{ New(string) APIClient }
type OCIRegistry interface {
	PushSources(context.Context, oci.Reference, []byte, []oci.SourceBlob) (string, error)
	PushAdversaryManifestReferrer(context.Context, oci.Reference, string, []byte) (string, string, error)
	PullSources(context.Context, oci.Reference) (*oci.PulledSources, error)
	Resolve(context.Context, oci.Reference) (string, error)
	SetPlainHTTP(bool)
}
type RegistryFactory interface {
	New(string, string) (OCIRegistry, error)
}
type Repository interface {
	BindingIdentity() string
	Resolve(string) (repository.Record, error)
	PlanGC() (repository.GCPlan, error)
	ApplyGC(repository.GCPlan, bool) (repository.GCReport, error)
	CheckAll() (repository.CheckReport, error)
	RepairAll(map[string]blobsource.Source) (repository.RepairReport, error)
	DeleteRef(string, string) error
	MigrationStatus(string) (repository.MigrationStatus, error)
	LeaseMaterialized(repository.Record) (*repository.MaterializationLease, error)
}
type Resolution struct {
	CanonicalReference, Digest, Path string
	Local                            bool
	Record                           repository.Record
}
type Resolver interface {
	BindingIdentity() string
	Resolve(context.Context, string) (Resolution, error)
	Lookup(context.Context, string) (Resolution, error)
	ResolveRecord(string) (repository.Record, error)
	HasExact(string) (bool, error)
	Entries(int) ([]repository.Entry, error)
	CanonicalReferenceFor(string, string) (string, error)
	Inventory(repository.Record) ([]pack.File, error)
	PayloadSources(repository.Record) (*repository.PayloadLease, error)
	ImportPacked(pack.Artifact, string) (repository.Record, error)
	ImportSources(repository.SourceImport) (repository.Record, error)
	CommitEquivalentManifest(string, string, []byte) (repository.Record, error)
	UpdateRef(string, string, string) error
}
type Runtime interface {
	BindingIdentity() string
	Run(context.Context, AdversaryRunOptions) error
	Inspect(context.Context, AdversaryRunOptions) error
	Auto(context.Context, AdversaryAutoOptions) (AdversaryAutoResult, error)
}
type AdversaryRunOptions struct {
	AdversaryRef, RepoPath, BaseRef, HeadRef, Builder, Format string
	Force, KeepTemp, NoNetwork, Verbose, IncludeSuppressed    bool
	Shell, AllFiles, AllowUnsafeHostExecution                 bool
	Build                                                     bool
	RunTimeout, BuildTimeout                                  time.Duration
	Stdout, Stderr                                            io.Writer
	ReviewContext                                             *detection.Context
}
type AdversaryAutoOptions struct {
	ChangeArgument, RepoPath                       string
	MinimumConfidence                              detection.Confidence
	Includes, Excludes                             []string
	All, DryRun, Explain, AllowUnsafeHostExecution bool
	IncludeSuppressed                              bool
	RunTimeout, DetectionTimeout                   time.Duration
	Stdout, Stderr                                 io.Writer
	ReportSelections                               func(AdversaryAutoResult) error
}
type AdversaryAutoCandidate struct {
	Name, Reference, Digest string
}
type AdversaryAutoSelection struct {
	Candidate                  AdversaryAutoCandidate
	Result                     detection.Result
	Selected, Forced, Excluded bool
	Error                      error
}
type AdversaryAutoResult struct {
	Context    detection.Context
	Selections []AdversaryAutoSelection
	Findings   int
	RunErrors  []error
}
type BrowserAuthRequest struct {
	Client APIClient
	Name   string
	CI     bool
	Output io.Writer
}
type BrowserAuth interface {
	Login(context.Context, BrowserAuthRequest) (adversarylabs.TokenResponse, error)
}
type TTY interface {
	Interactive(io.Reader) bool
	ReadSecret(context.Context, io.Reader, io.Writer) ([]byte, error)
}

type Dependencies struct {
	Stdin          io.Reader
	Stdout, Stderr io.Writer
	Clock          Clock
	Projects       Projects
	References     References
	Auth           AuthStore
	API            APIFactory
	Registries     RegistryFactory
	DefaultAPIURL  string
	RegistryHost   string
	RegistryNS     string
	Repository     Repository
	Resolver       Resolver
	Runtime        Runtime
	BrowserAuth    BrowserAuth
	TTY            TTY
}

type App struct{ deps Dependencies }
type Validatable interface{ Validate() error }
type BindingIdentity interface{ BindingIdentity() string }

func New(deps Dependencies) (*App, error) {
	missing := []string{}
	if deps.Stdin == nil {
		missing = append(missing, "stdin")
	}
	if deps.Stdout == nil {
		missing = append(missing, "stdout")
	}
	if deps.Stderr == nil {
		missing = append(missing, "stderr")
	}
	if deps.Clock == nil {
		missing = append(missing, "clock")
	}
	if deps.Projects == nil {
		missing = append(missing, "projects")
	}
	if deps.References == nil {
		missing = append(missing, "references")
	}
	if deps.Auth == nil {
		missing = append(missing, "auth store")
	}
	if deps.API == nil {
		missing = append(missing, "api factory")
	}
	if deps.Registries == nil {
		missing = append(missing, "registry factory")
	}
	if deps.DefaultAPIURL == "" {
		missing = append(missing, "default api url")
	}
	if deps.RegistryHost == "" {
		missing = append(missing, "registry host")
	}
	if deps.Repository == nil {
		missing = append(missing, "repository")
	}
	if deps.Resolver == nil {
		missing = append(missing, "resolver")
	}
	if deps.Runtime == nil {
		missing = append(missing, "runtime")
	}
	if deps.BrowserAuth == nil {
		missing = append(missing, "browser auth")
	}
	if deps.TTY == nil {
		missing = append(missing, "tty")
	}
	if len(missing) > 0 {
		return nil, &Error{Operation: "construct", Kind: "missing-dependency", Err: fmt.Errorf("missing %v", missing)}
	}
	authBinding, authOK := deps.Auth.(BindingIdentity)
	apiBinding, apiOK := deps.API.(BindingIdentity)
	registryBinding, registryOK := deps.Registries.(BindingIdentity)
	if !authOK || !apiOK || !registryOK {
		return nil, &Error{Operation: "construct", Kind: "invalid-dependency", Resource: "auth/api/registry", Err: fmt.Errorf("dependency binding identity unavailable")}
	}
	identities := []string{authBinding.BindingIdentity(), apiBinding.BindingIdentity(), registryBinding.BindingIdentity()}
	for _, identity := range identities {
		if identity == "" || identity != identities[0] {
			return nil, &Error{Operation: "construct", Kind: "invalid-dependency", Resource: "auth/api/registry", Err: fmt.Errorf("dependency binding identity mismatch")}
		}
	}
	repositoryIdentity := deps.Repository.BindingIdentity()
	resolverIdentity := deps.Resolver.BindingIdentity()
	runtimeIdentity := deps.Runtime.BindingIdentity()
	if repositoryIdentity == "" || resolverIdentity == "" || runtimeIdentity == "" || repositoryIdentity != resolverIdentity || repositoryIdentity != runtimeIdentity {
		return nil, &Error{Operation: "construct", Kind: "invalid-dependency", Resource: "repository/resolver/runtime", Err: fmt.Errorf("dependency binding identity mismatch")}
	}
	validators := []Validatable{}
	if v, ok := deps.Clock.(Validatable); ok {
		validators = append(validators, v)
	}
	if v, ok := deps.BrowserAuth.(Validatable); ok {
		validators = append(validators, v)
	}
	if v, ok := deps.Auth.(Validatable); ok {
		validators = append(validators, v)
	}
	if v, ok := deps.API.(Validatable); ok {
		validators = append(validators, v)
	}
	if v, ok := deps.Registries.(Validatable); ok {
		validators = append(validators, v)
	}
	for _, validatable := range validators {
		if err := validatable.Validate(); err != nil {
			return nil, &Error{Operation: "construct", Kind: "invalid-dependency", Err: err}
		}
	}
	return &App{deps: deps}, nil
}

func (a *App) Dependencies() Dependencies { return a.deps }

type Error struct {
	Operation, Kind, Resource string
	Err                       error
}

func (e *Error) Error() string {
	if e.Resource != "" {
		return fmt.Sprintf("%s %s %s: %v", e.Operation, e.Kind, e.Resource, e.Err)
	}
	return fmt.Sprintf("%s %s: %v", e.Operation, e.Kind, e.Err)
}
func (e *Error) Unwrap() error { return e.Err }
func IsKind(err error, kind string) bool {
	var target *Error
	return errors.As(err, &target) && target.Kind == kind
}
