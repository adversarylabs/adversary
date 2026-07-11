// Package application defines the process-global-free application boundary.
// Command wiring is intentionally deferred to the migration phase.
package application

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/adversarylabs/adversary/pkg/oci"
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
type Environment interface{ Lookup(string) (string, bool) }
type Config interface {
	Get(context.Context, string) (string, error)
	Set(context.Context, string, string) error
}
type Paths interface {
	DataDir() (string, error)
	ConfigDir() (string, error)
	TempDir() string
}
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}
type Credentials interface {
	Credentials(string) (oci.Credentials, bool)
}
type Registry interface {
	Push(context.Context, oci.Reference, []byte, []oci.Blob) (string, error)
	Pull(context.Context, oci.Reference) (oci.PulledArtifact, error)
	Resolve(context.Context, oci.Reference) (string, error)
}
type Repository interface {
	Resolve(string) (repository.Record, error)
	PlanGC() (repository.GCPlan, error)
	ApplyGC(repository.GCPlan, bool) (repository.GCReport, error)
	CheckAll() (repository.CheckReport, error)
	RepairAll(map[string][]byte) (repository.RepairReport, error)
	DeleteRef(string, string) error
	MigrationStatus(string) (repository.MigrationStatus, error)
	LeaseMaterialized(repository.Record) (*repository.MaterializationLease, error)
}
type Resolution struct {
	Reference, Digest, Path string
	Local                   bool
}
type Resolver interface {
	Resolve(context.Context, string) (Resolution, error)
}
type Runtime interface {
	Run(context.Context, []string, RunOptions) error
}
type RunOptions struct {
	Dir            string
	Env            []string
	Stdin          io.Reader
	Stdout, Stderr io.Writer
}
type Browser interface {
	Open(context.Context, string) error
}
type TTY interface {
	Interactive(io.Reader) bool
	ReadSecret(context.Context, io.Reader, io.Writer) ([]byte, error)
}

type Dependencies struct {
	Stdin          io.Reader
	Stdout, Stderr io.Writer
	Clock          Clock
	Env            Environment
	Config         Config
	Paths          Paths
	HTTP           HTTPClient
	Credentials    Credentials
	Registry       Registry
	Repository     Repository
	Resolver       Resolver
	Runtime        Runtime
	Browser        Browser
	TTY            TTY
}

type App struct{ deps Dependencies }
type Validatable interface{ Validate() error }

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
	if deps.Env == nil {
		missing = append(missing, "environment")
	}
	if deps.Config == nil {
		missing = append(missing, "config")
	}
	if deps.Paths == nil {
		missing = append(missing, "paths")
	}
	if deps.HTTP == nil {
		missing = append(missing, "http")
	}
	if deps.Credentials == nil {
		missing = append(missing, "credentials")
	}
	if deps.Registry == nil {
		missing = append(missing, "registry")
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
	if deps.Browser == nil {
		missing = append(missing, "browser")
	}
	if deps.TTY == nil {
		missing = append(missing, "tty")
	}
	if len(missing) > 0 {
		return nil, &Error{Operation: "construct", Kind: "missing-dependency", Err: fmt.Errorf("missing %v", missing)}
	}
	for _, dep := range []any{deps.Clock, deps.Env, deps.HTTP, deps.Browser} {
		if validatable, ok := dep.(Validatable); ok {
			if err := validatable.Validate(); err != nil {
				return nil, &Error{Operation: "construct", Kind: "invalid-dependency", Err: err}
			}
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
