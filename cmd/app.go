package cmd

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"time"

	internaladversary "github.com/adversarylabs/adversary/internal/adversary"
	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/internal/dependencies"
	"github.com/adversarylabs/adversary/pkg/oci"
	"golang.org/x/term"
)

type processTimer struct{ *time.Timer }

func (t processTimer) C() <-chan time.Time { return t.Timer.C }

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
	return application.Resolution{Reference: got.CanonicalReference, Digest: got.Digest, Path: got.Path, Local: got.Local}, err
}
func (p processResolver) InternalResolver() internaladversary.Resolver { return p.resolver }
func (p processResolver) RepositoryIdentity() string                   { return p.resolver.Repository.RootPath() }

type processRuntime struct{}

func (processRuntime) Run(ctx context.Context, args []string, opts application.RunOptions) error {
	if len(args) == 0 {
		return fmt.Errorf("runtime command required")
	}
	c := exec.CommandContext(ctx, args[0], args[1:]...)
	c.Dir = opts.Dir
	c.Env = opts.Env
	c.Stdin = opts.Stdin
	c.Stdout = opts.Stdout
	c.Stderr = opts.Stderr
	return c.Run()
}

type processTTY struct{}

func (processTTY) Interactive(r io.Reader) bool {
	f, ok := r.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}
func (processTTY) ReadSecret(ctx context.Context, r io.Reader, w io.Writer) ([]byte, error) {
	f, ok := r.(*os.File)
	if !ok {
		return nil, fmt.Errorf("secret input is not a terminal")
	}
	return term.ReadPassword(int(f.Fd()))
}

func newProcessApp(stdin io.Reader, stdout, stderr io.Writer) (*application.App, error) {
	resolver, err := internaladversary.DefaultResolver()
	if err != nil {
		return nil, err
	}
	registry := oci.NewHTTPRegistry()
	return application.New(application.Dependencies{Stdin: stdin, Stdout: stdout, Stderr: stderr, Clock: dependencies.Clock{NowFunc: time.Now, TimerFunc: func(d time.Duration) application.Timer { return processTimer{time.NewTimer(d)} }}, Env: dependencies.Environment{LookupFunc: os.LookupEnv}, Config: processConfig{}, Paths: processPaths{data: resolver.Repository.Root}, HTTP: dependencies.HTTPClient{DoFunc: http.DefaultClient.Do}, Credentials: oci.DockerCredentialStore{}, Registry: registry, Repository: resolver.Repository, Resolver: processResolver{resolver: resolver}, Runtime: processRuntime{}, Browser: dependencies.Browser{OpenFunc: func(ctx context.Context, u string) error { return openBrowser(u) }}, TTY: processTTY{}})
}
