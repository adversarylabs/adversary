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

func TestRunWithoutRefsForwardsSelectionControls(t *testing.T) {
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
	// --no-pull keeps this unit test offline; zero-arg run otherwise pulls the catalog.
	cmd.SetArgs([]string{
		"run", "--path", "/repo", "--base", "main", "--head", "HEAD",
		"--dry-run", "--explain", "--no-pull", "--min-confidence", "high",
		"--include", "security", "--include", "complexity", "--exclude", "repository",
		"--model-provider", "fireworks", "--model", "accounts/fireworks/models/glm-5p2",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if stub.opts.RepoPath != "/repo" || stub.opts.BaseRef != "main" || stub.opts.HeadRef != "HEAD" ||
		!stub.opts.DryRun || !stub.opts.Explain || stub.opts.MinimumConfidence != detection.ConfidenceHigh ||
		len(stub.opts.Includes) != 2 || len(stub.opts.Excludes) != 1 ||
		stub.opts.ModelProvider != "fireworks" || stub.opts.Model != "accounts/fireworks/models/glm-5p2" {
		t.Fatalf("options = %#v", stub.opts)
	}
	wantFragments := []string{"Running 1 adversaries", "dockerfile", "high", "Dockerfile changed", "files: Dockerfile", "repository", "skipped", "--exclude"}
	for _, fragment := range wantFragments {
		if !bytes.Contains(stdout.Bytes(), []byte(fragment)) {
			t.Fatalf("output missing %q:\n%s", fragment, stdout.String())
		}
	}
}

func TestRunWithoutRefsNoMatchIsSuccessfulAndConcise(t *testing.T) {
	var stdout, stderr bytes.Buffer
	base := lifecycleTestApp(t, repository.Repository{Root: t.TempDir()}, &stdout, &stderr)
	deps := base.Dependencies()
	deps.Runtime = &autoStubRuntime{inner: deps.Runtime}
	app, err := application.New(deps)
	if err != nil {
		t.Fatal(err)
	}
	cmd := NewRootCommandWithApp(app)
	cmd.SetArgs([]string{"run", "--dry-run", "--no-pull"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if got := stdout.String(); got != "No relevant adversaries detected for this change.\n" {
		t.Fatalf("output = %q", got)
	}
}

func TestRunWithoutRefsNoPullSkipsRemoteEnsure(t *testing.T) {
	var stdout, stderr bytes.Buffer
	base := lifecycleTestApp(t, repository.Repository{Root: t.TempDir()}, &stdout, &stderr)
	deps := base.Dependencies()
	stub := &autoStubRuntime{inner: deps.Runtime}
	deps.Runtime = stub
	app, err := application.New(deps)
	if err != nil {
		t.Fatal(err)
	}
	cmd := NewRootCommandWithApp(app)
	cmd.SetArgs([]string{"run", "--dry-run", "--no-pull"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stderr.String(), "Ensuring") || strings.Contains(stderr.String(), "could not list remote") {
		t.Fatalf("expected no remote ensure with --no-pull, stderr=%q", stderr.String())
	}
}

func TestRunWithRefsRejectsAutomaticOnlyFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	app := lifecycleTestApp(t, repository.Repository{Root: t.TempDir()}, &stdout, &stderr)
	cmd := NewRootCommandWithApp(app)
	cmd.SetArgs([]string{"run", "example", "--all"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "--all") {
		t.Fatalf("err = %v", err)
	}
}

func TestRenderRunSelectionsReturnsOutputFailureAndEscapesHostilePath(t *testing.T) {
	result := application.AdversaryAutoResult{Selections: []application.AdversaryAutoSelection{{
		Candidate: application.AdversaryAutoCandidate{Name: "security"}, Selected: true,
		Result: detection.Result{Confidence: detection.ConfidenceHigh, Reasons: []string{"matched"}, RelevantFiles: []string{"safe.go\nforged heading"}},
	}}}
	var output bytes.Buffer
	if err := renderRunSelections(&output, result, true); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "safe.go\nforged heading") || !strings.Contains(output.String(), `"safe.go\nforged heading"`) {
		t.Fatalf("unsafe output = %q", output.String())
	}
	if err := renderRunSelections(failingAutoWriter{}, result, true); err == nil || !strings.Contains(err.Error(), "closed output") {
		t.Fatalf("output error = %v", err)
	}
}

func TestRunWithoutRefsJSONKeepsSelectionOffStdout(t *testing.T) {
	var stdout, stderr bytes.Buffer
	base := lifecycleTestApp(t, repository.Repository{Root: t.TempDir()}, &stdout, &stderr)
	deps := base.Dependencies()
	stub := &autoStubRuntime{inner: deps.Runtime, result: application.AdversaryAutoResult{Selections: []application.AdversaryAutoSelection{
		{Candidate: application.AdversaryAutoCandidate{Name: "dockerfile"}, Result: detection.Result{Applicable: true, Confidence: detection.ConfidenceHigh, Reasons: []string{"Dockerfile changed"}}, Selected: true},
	}}}
	deps.Runtime = stub
	app, err := application.New(deps)
	if err != nil {
		t.Fatal(err)
	}
	cmd := NewRootCommandWithApp(app)
	cmd.SetArgs([]string{"run", "--dry-run", "--no-pull", "--format", "json", "--explain"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("JSON mode must not write selection text to stdout: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "Running 1 adversaries") || !strings.Contains(stderr.String(), "dockerfile") {
		t.Fatalf("expected selection narrative on stderr, got %q", stderr.String())
	}
}
