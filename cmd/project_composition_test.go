package cmd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/pkg/oci"
	"github.com/adversarylabs/adversary/pkg/pack"
	"github.com/adversarylabs/adversary/pkg/repository"
)

type recordingProjects struct {
	initCalls, validateCalls, checkCalls, packCalls int
}

func (p *recordingProjects) Init(opts application.ProjectInitOptions) (application.ProjectInitResult, error) {
	p.initCalls++
	return application.ProjectInitResult{Location: "/injected/" + opts.Destination, SDK: "Injected"}, nil
}
func (p *recordingProjects) RenderInit(w io.Writer, result application.ProjectInitResult, _ string) {
	_, _ = io.WriteString(w, result.Location)
}
func (p *recordingProjects) Validate(context.Context, string, application.Resolver) (application.ProjectValidation, error) {
	p.validateCalls++
	return application.ProjectValidation{Path: "/injected/adversary.yaml", Name: "injected", Runtime: "node"}, nil
}
func (p *recordingProjects) Check(pack.Options) (pack.Preflight, error) {
	p.checkCalls++
	return pack.Preflight{Name: "injected", Version: "1.0.0", Runtime: "node"}, nil
}
func (p *recordingProjects) Pack(context.Context, pack.Options) (pack.Artifact, error) {
	p.packCalls++
	return pack.Artifact{}, errors.New("injected pack stop")
}

func TestProjectCommandsUseInjectedProjectPort(t *testing.T) {
	var stdout, stderr bytes.Buffer
	base := lifecycleTestApp(t, repository.Repository{Root: t.TempDir()}, &stdout, &stderr).Dependencies()
	projects := &recordingProjects{}
	base.Projects = projects
	app, err := application.New(base)
	if err != nil {
		t.Fatal(err)
	}

	for _, args := range [][]string{{"init", "example"}, {"validate", "anything"}, {"pack", "anything", "--check"}} {
		root := NewRootCommandWithApp(app)
		root.SetArgs(args)
		if err := root.Execute(); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	}
	root := NewRootCommandWithApp(app)
	root.SetArgs([]string{"pack", "anything"})
	if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "injected pack stop") {
		t.Fatalf("pack error=%v", err)
	}
	if projects.initCalls != 1 || projects.validateCalls != 1 || projects.checkCalls != 1 || projects.packCalls != 1 {
		t.Fatalf("project calls init=%d validate=%d check=%d pack=%d", projects.initCalls, projects.validateCalls, projects.checkCalls, projects.packCalls)
	}
}

type errorReferences struct {
	called string
	err    error
}

func (r *errorReferences) Parse(value string) (oci.Reference, error) {
	r.called = value
	return oci.Reference{}, r.err
}

func TestPullUsesInjectedCapturedReferenceParser(t *testing.T) {
	var stdout, stderr bytes.Buffer
	base := lifecycleTestApp(t, repository.Repository{Root: t.TempDir()}, &stdout, &stderr).Dependencies()
	want := errors.New("injected parser")
	refs := &errorReferences{err: want}
	base.References = refs
	app, err := application.New(base)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("ADVERSARY_REGISTRY_HOST", "poison.invalid")
	root := NewRootCommandWithApp(app)
	root.SetArgs([]string{"pull", "reviewer"})
	if err := root.Execute(); !errors.Is(err, want) {
		t.Fatalf("error=%v", err)
	}
	if refs.called != "reviewer" {
		t.Fatalf("parsed=%q", refs.called)
	}
}

func TestProcessReferenceDefaultsAreCaptured(t *testing.T) {
	refs := processReferences{registry: "registry.example", namespace: "team"}
	t.Setenv("ADVERSARY_REGISTRY_HOST", "poison.invalid")
	got, err := refs.Parse("reviewer:1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Registry != "registry.example" || got.Repository != "team/reviewer" {
		t.Fatalf("reference=%#v", got)
	}
}

func TestPackBuildUsesCapturedEnvironmentAndInjectedRunner(t *testing.T) {
	project := t.TempDir()
	writeProject(t, project)
	if err := os.WriteFile(filepath.Join(project, "package.json"), []byte(`{"scripts":{"build":"hostile-command"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(project, "node_modules"), 0700); err != nil {
		t.Fatal(err)
	}
	calls := 0
	build := pack.BuildEnvironment{NPM: "/captured/npm", Node: "/captured/node", Docker: "/captured/docker", Environment: []string{"PATH=/captured", "HOME=/captured/home", "MARKER=captured"}, Run: func(_ context.Context, executable string, args []string, dir string, env []string, _ io.Writer, _ io.Writer, capture bool) ([]byte, error) {
		calls++
		if !strings.Contains(strings.Join(env, "\n"), "MARKER=captured") {
			t.Fatalf("environment=%v", env)
		}
		if capture {
			if executable != "/captured/node" {
				t.Fatalf("node=%q", executable)
			}
			return []byte("v22.99.0\n"), nil
		}
		if executable != "/captured/npm" || strings.Join(args, " ") != "run build" {
			t.Fatalf("run %q %v", executable, args)
		}
		if err := os.MkdirAll(filepath.Join(dir, "dist"), 0700); err != nil {
			return nil, err
		}
		return nil, os.WriteFile(filepath.Join(dir, "dist", "index.js"), []byte("built"), 0600)
	}}
	refs := processReferences{registry: "registry.example", namespace: "team"}
	projects := processProjects{references: refs, build: build}
	t.Setenv("PATH", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	artifact, err := projects.Pack(context.Background(), pack.Options{Dir: project, Build: true, Builder: "local"})
	if err != nil {
		t.Fatal(err)
	}
	defer artifact.Close()
	if calls != 2 {
		t.Fatalf("runner calls=%d", calls)
	}
}
