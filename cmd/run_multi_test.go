package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	internaladversary "github.com/adversarylabs/adversary/internal/adversary"
	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/pkg/repository"
)

type multiRecordingRuntime struct {
	inner        application.Runtime
	refs         []string
	opts         []application.AdversaryRunOptions
	errs         map[string]error
	stdoutBodies map[string]string
}

func (r *multiRecordingRuntime) BindingIdentity() string {
	return r.inner.(application.BindingIdentity).BindingIdentity()
}
func (r *multiRecordingRuntime) Run(_ context.Context, opts application.AdversaryRunOptions) error {
	r.refs = append(r.refs, opts.AdversaryRef)
	r.opts = append(r.opts, opts)
	if opts.Stdout != nil {
		if r.stdoutBodies != nil {
			if body, ok := r.stdoutBodies[opts.AdversaryRef]; ok {
				_, _ = opts.Stdout.Write([]byte(body))
			}
		} else if opts.Format == "json" {
			// Minimal JSON body so multi-json capture is non-empty.
			_, _ = opts.Stdout.Write([]byte(`{"protocolVersion":1,"result":{"findings":[]}}` + "\n"))
		} else {
			_, _ = opts.Stdout.Write([]byte("ok report for " + opts.AdversaryRef + "\n"))
		}
	}
	if r.errs != nil {
		if err, ok := r.errs[opts.AdversaryRef]; ok {
			return err
		}
	}
	return nil
}
func (r *multiRecordingRuntime) Inspect(ctx context.Context, opts application.AdversaryRunOptions) error {
	return r.inner.Inspect(ctx, opts)
}
func (r *multiRecordingRuntime) Auto(ctx context.Context, opts application.AdversaryAutoOptions) (application.AdversaryAutoResult, error) {
	return r.inner.Auto(ctx, opts)
}

func TestRunAcceptsMultipleAdversaryPositionals(t *testing.T) {
	var out, errOut bytes.Buffer
	base := lifecycleTestApp(t, repository.Repository{Root: t.TempDir()}, &out, &errOut)
	deps := base.Dependencies()
	spy := &multiRecordingRuntime{inner: deps.Runtime}
	deps.Runtime = spy
	app, err := application.New(deps)
	if err != nil {
		t.Fatal(err)
	}
	cmd := NewRootCommandWithApp(app)
	cmd.SetArgs([]string{"run", "go-cli", "secrets", "--path", "/repo", "--all-files"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if len(spy.refs) != 2 || spy.refs[0] != "go-cli" || spy.refs[1] != "secrets" {
		t.Fatalf("refs = %#v", spy.refs)
	}
	for _, o := range spy.opts {
		if o.RepoPath != "/repo" || !o.AllFiles {
			t.Fatalf("shared options not applied: %#v", o)
		}
	}
	if !strings.Contains(out.String(), "=== go-cli ===") || !strings.Contains(out.String(), "=== secrets ===") {
		t.Fatalf("missing section headers:\n%s", out.String())
	}
	if !strings.Contains(errOut.String(), "Ran 2 adversaries") {
		t.Fatalf("missing footer: %q", errOut.String())
	}
}

func TestRunMultipleJSONConcatenatesResultsEnvelope(t *testing.T) {
	var out, errOut bytes.Buffer
	base := lifecycleTestApp(t, repository.Repository{Root: t.TempDir()}, &out, &errOut)
	deps := base.Dependencies()
	spy := &multiRecordingRuntime{inner: deps.Runtime}
	deps.Runtime = spy
	app, err := application.New(deps)
	if err != nil {
		t.Fatal(err)
	}
	cmd := NewRootCommandWithApp(app)
	cmd.SetArgs([]string{"run", "a", "b", "--format", "json"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Command string `json:"command"`
		Data    struct {
			Results []struct {
				Adversary string          `json:"adversary"`
				Output    json.RawMessage `json:"output"`
			} `json:"results"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &envelope); err != nil {
		t.Fatalf("json: %v\n%s", err, out.String())
	}
	if envelope.Command != "run" || len(envelope.Data.Results) != 2 {
		t.Fatalf("envelope = %#v", envelope)
	}
	if envelope.Data.Results[0].Adversary != "a" || envelope.Data.Results[1].Adversary != "b" {
		t.Fatalf("adversaries = %#v", envelope.Data.Results)
	}
	if len(envelope.Data.Results[0].Output) == 0 {
		t.Fatal("expected captured per-adversary JSON output")
	}
}

func TestRunMultipleJSONKeepsEnvelopeWhenStdoutIsNotJSON(t *testing.T) {
	var out, errOut bytes.Buffer
	base := lifecycleTestApp(t, repository.Repository{Root: t.TempDir()}, &out, &errOut)
	deps := base.Dependencies()
	spy := &multiRecordingRuntime{
		inner: deps.Runtime,
		errs: map[string]error{
			"broken": errors.New("child crashed"),
		},
		// Write non-JSON stdout for the failing adversary before returning the error.
		stdoutBodies: map[string]string{
			"broken": "panic: boom\nnot json\n",
			"ok":     `{"protocolVersion":1,"result":{"findings":[]}}` + "\n",
		},
	}
	deps.Runtime = spy
	app, err := application.New(deps)
	if err != nil {
		t.Fatal(err)
	}
	cmd := NewRootCommandWithApp(app)
	cmd.SetArgs([]string{"run", "broken", "ok", "--format", "json"})
	runErr := cmd.Execute()
	if runErr == nil {
		t.Fatal("expected hard error from broken adversary")
	}
	var envelope struct {
		Command string `json:"command"`
		Data    struct {
			Results []struct {
				Adversary string          `json:"adversary"`
				Output    json.RawMessage `json:"output"`
				Error     string          `json:"error"`
			} `json:"results"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &envelope); err != nil {
		t.Fatalf("multi-run envelope must remain valid JSON: %v\n%s", err, out.String())
	}
	if len(envelope.Data.Results) != 2 {
		t.Fatalf("results = %#v", envelope.Data.Results)
	}
	broken := envelope.Data.Results[0]
	if broken.Adversary != "broken" {
		t.Fatalf("first result = %#v", broken)
	}
	if len(broken.Output) != 0 {
		t.Fatalf("non-JSON stdout must not be stored as RawMessage: %s", broken.Output)
	}
	if !strings.Contains(broken.Error, "child crashed") || !strings.Contains(broken.Error, "non-JSON") {
		t.Fatalf("error = %q", broken.Error)
	}
	if len(envelope.Data.Results[1].Output) == 0 {
		t.Fatal("second adversary should keep valid JSON output")
	}
}

func TestRunMultipleAggregatesFindingsExit(t *testing.T) {
	var out, errOut bytes.Buffer
	base := lifecycleTestApp(t, repository.Repository{Root: t.TempDir()}, &out, &errOut)
	deps := base.Dependencies()
	spy := &multiRecordingRuntime{
		inner: deps.Runtime,
		errs: map[string]error{
			"a": &internaladversary.FindingsError{Count: 2},
			"b": &internaladversary.FindingsError{Count: 3},
		},
	}
	deps.Runtime = spy
	app, err := application.New(deps)
	if err != nil {
		t.Fatal(err)
	}
	cmd := NewRootCommandWithApp(app)
	cmd.SetArgs([]string{"run", "a", "b"})
	err = cmd.Execute()
	var findings *internaladversary.FindingsError
	if !errors.As(err, &findings) || findings.Count != 5 {
		t.Fatalf("err = %v, want FindingsError count 5", err)
	}
	if !strings.Contains(errOut.String(), "findings: 5") {
		t.Fatalf("footer missing findings: %q", errOut.String())
	}
}

func TestRunMultipleRejectsShell(t *testing.T) {
	var out, errOut bytes.Buffer
	base := lifecycleTestApp(t, repository.Repository{Root: t.TempDir()}, &out, &errOut)
	deps := base.Dependencies()
	spy := &countingRuntime{inner: deps.Runtime}
	deps.Runtime = spy
	app, err := application.New(deps)
	if err != nil {
		t.Fatal(err)
	}
	cmd := NewRootCommandWithApp(app)
	cmd.SetArgs([]string{"run", "a", "b", "--shell"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error")
	}
	if spy.calls != 0 {
		t.Fatalf("runtime work on invalid flags: %d", spy.calls)
	}
}

func TestRunSingleStillWorksWithoutSectionHeaders(t *testing.T) {
	var out, errOut bytes.Buffer
	base := lifecycleTestApp(t, repository.Repository{Root: t.TempDir()}, &out, &errOut)
	deps := base.Dependencies()
	spy := &multiRecordingRuntime{inner: deps.Runtime}
	deps.Runtime = spy
	app, err := application.New(deps)
	if err != nil {
		t.Fatal(err)
	}
	cmd := NewRootCommandWithApp(app)
	cmd.SetArgs([]string{"run", "only-one"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "===") {
		t.Fatalf("single run should not use multi headers: %q", out.String())
	}
	if strings.Contains(errOut.String(), "Ran ") {
		t.Fatalf("single run should not print multi footer: %q", errOut.String())
	}
}
