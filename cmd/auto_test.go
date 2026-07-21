package cmd

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/pkg/detection"
	"github.com/adversarylabs/adversary/pkg/repository"
	"github.com/spf13/cobra"
)

type failingAutoWriter struct{}

func (failingAutoWriter) Write([]byte) (int, error) { return 0, errors.New("closed output") }

type autoStubRuntime struct {
	inner  application.Runtime
	opts   application.AdversaryAutoOptions
	result application.AdversaryAutoResult
}

func (r *autoStubRuntime) BindingIdentity() string { return r.inner.BindingIdentity() }
func (r *autoStubRuntime) Run(ctx context.Context, opts application.AdversaryRunOptions) error {
	return r.inner.Run(ctx, opts)
}
func (r *autoStubRuntime) Inspect(ctx context.Context, opts application.AdversaryRunOptions) error {
	return r.inner.Inspect(ctx, opts)
}
func (r *autoStubRuntime) Auto(_ context.Context, opts application.AdversaryAutoOptions) (application.AdversaryAutoResult, error) {
	r.opts = opts
	if opts.ReportSelections != nil {
		if err := opts.ReportSelections(r.result); err != nil {
			return r.result, err
		}
	}
	return r.result, nil
}

func TestAutoCommandForwardsControlsAndExplainsSelections(t *testing.T) {
	var stdout, stderr bytes.Buffer
	base := lifecycleTestApp(t, repository.Repository{Root: t.TempDir()}, &stdout, &stderr)
	deps := base.Dependencies()
	stub := &autoStubRuntime{inner: deps.Runtime, result: application.AdversaryAutoResult{Selections: []application.AdversaryAutoSelection{
		{Candidate: application.AdversaryAutoCandidate{Name: "dockerfile"}, Result: detection.Result{Applicable: true, Confidence: detection.ConfidenceHigh, Reasons: []string{"Dockerfile changed"}, RelevantFiles: []string{"Dockerfile"}}, Selected: true},
		{Candidate: application.AdversaryAutoCandidate{Name: "repository"}, Result: detection.Result{Confidence: detection.ConfidenceLow, Reasons: []string{"repository matched, but this change did not match"}}, Excluded: true},
	}}}
	deps.Runtime = stub
	app, err := application.New(deps)
	if err != nil {
		t.Fatal(err)
	}
	cmd := NewRootCommandWithApp(app)
	cmd.SetArgs([]string{"auto", "main...HEAD", "--repo", "/repo", "--dry-run", "--explain", "--min-confidence", "high", "--include", "security", "--include", "complexity", "--exclude", "repository"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if stub.opts.ChangeArgument != "main...HEAD" || stub.opts.RepoPath != "/repo" || !stub.opts.DryRun || !stub.opts.Explain || stub.opts.MinimumConfidence != detection.ConfidenceHigh || len(stub.opts.Includes) != 2 || len(stub.opts.Excludes) != 1 {
		t.Fatalf("options = %#v", stub.opts)
	}
	wantFragments := []string{"Detected 1 relevant adversaries", "dockerfile", "high confidence", "Dockerfile changed", "relevant files: Dockerfile", "repository (skipped)", "excluded by --exclude"}
	for _, fragment := range wantFragments {
		if !bytes.Contains(stdout.Bytes(), []byte(fragment)) {
			t.Fatalf("output missing %q:\n%s", fragment, stdout.String())
		}
	}
}

func TestAutoCommandNoMatchIsSuccessfulAndConcise(t *testing.T) {
	var stdout, stderr bytes.Buffer
	base := lifecycleTestApp(t, repository.Repository{Root: t.TempDir()}, &stdout, &stderr)
	deps := base.Dependencies()
	deps.Runtime = &autoStubRuntime{inner: deps.Runtime}
	app, err := application.New(deps)
	if err != nil {
		t.Fatal(err)
	}
	cmd := NewRootCommandWithApp(app)
	cmd.SetArgs([]string{"auto", "--dry-run"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if got := stdout.String(); got != "No relevant adversaries detected for this change.\n" {
		t.Fatalf("output = %q", got)
	}
}

func TestRenderAutoSelectionsReturnsOutputFailureAndEscapesHostilePath(t *testing.T) {
	result := application.AdversaryAutoResult{Selections: []application.AdversaryAutoSelection{{
		Candidate: application.AdversaryAutoCandidate{Name: "security"}, Selected: true,
		Result: detection.Result{Confidence: detection.ConfidenceHigh, Reasons: []string{"matched"}, RelevantFiles: []string{"safe.go\nforged heading"}},
	}}}
	command := &cobra.Command{}
	var output bytes.Buffer
	command.SetOut(&output)
	if err := renderAutoSelections(command, result, true); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "safe.go\nforged heading") || !strings.Contains(output.String(), `"safe.go\nforged heading"`) {
		t.Fatalf("unsafe output = %q", output.String())
	}
	command.SetOut(failingAutoWriter{})
	if err := renderAutoSelections(command, result, true); err == nil || !strings.Contains(err.Error(), "closed output") {
		t.Fatalf("output error = %v", err)
	}
}
