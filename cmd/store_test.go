package cmd

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	internaladversary "github.com/adversarylabs/adversary/internal/adversary"
	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/internal/dependencies"
	"github.com/adversarylabs/adversary/pkg/oci"
	"github.com/adversarylabs/adversary/pkg/pack"
	"github.com/adversarylabs/adversary/pkg/repository"
)

type injectedResolver struct{}

func (injectedResolver) Resolve(context.Context, string) (application.Resolution, error) {
	return application.Resolution{}, errors.New("unused")
}

func TestProcessAppResolverRepositoryBindingAccepted(t *testing.T) {
	t.Setenv("ADVERSARY_DATA_DIR", t.TempDir())
	app, err := newProcessApp(&bytes.Buffer{}, &bytes.Buffer{}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateAppRepositoryBinding(app); err != nil {
		t.Fatal(err)
	}
}

func lifecycleTestApp(t *testing.T, repo repository.Repository, stdout, stderr *bytes.Buffer) *application.App {
	t.Helper()
	app, err := application.New(application.Dependencies{Stdin: &bytes.Buffer{}, Stdout: stdout, Stderr: stderr, Clock: dependencies.Clock{NowFunc: func() time.Time { return time.Unix(1, 0) }, TimerFunc: func(time.Duration) application.Timer { return processTimer{time.NewTimer(time.Hour)} }}, Env: dependencies.Environment{LookupFunc: func(string) (string, bool) { return "", false }}, Config: processConfig{}, Paths: processPaths{data: repo.Root}, HTTP: dependencies.HTTPClient{DoFunc: func(*http.Request) (*http.Response, error) { return nil, errors.New("unused") }}, Credentials: oci.DockerCredentialStore{}, Registry: oci.NewHTTPRegistry(), Repository: repo, Resolver: processResolver{resolver: internaladversary.Resolver{Repository: repo}}, Runtime: processRuntime{}, Browser: dependencies.Browser{OpenFunc: func(context.Context, string) error { return nil }}, TTY: processTTY{}})
	if err != nil {
		t.Fatal(err)
	}
	return app
}

func TestStoreLifecycleJSONAndConfirmation(t *testing.T) {
	repo := repository.Repository{Root: t.TempDir()}
	project := t.TempDir()
	writeProject(t, project)
	a, err := pack.Create(context.Background(), pack.Options{Dir: project})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.ImportPacked(a, ""); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	app := lifecycleTestApp(t, repo, &out, &errOut)
	check := NewRootCommandWithApp(app)
	check.SetArgs([]string{"store", "check", "--json"})
	if err := check.Execute(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out.Bytes(), []byte(`"healthy":true`)) {
		t.Fatalf("output=%s", out.String())
	}
	if errOut.Len() != 0 {
		t.Fatalf("JSON stderr=%q", errOut.String())
	}
	out.Reset()
	gc := NewRootCommandWithApp(app)
	gc.SetArgs([]string{"store", "gc", "--json"})
	if err := gc.Execute(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out.Bytes(), []byte(`"dryRun":true`)) {
		t.Fatalf("output=%s", out.String())
	}
	apply := NewRootCommandWithApp(app)
	apply.SetArgs([]string{"store", "gc", "--apply"})
	if err := apply.Execute(); err == nil || !application.IsKind(err, "confirmation") {
		t.Fatal("destructive GC did not require confirmation")
	}
	refRec, err := repo.ImportPacked(a, "registry.example/team/test:1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	del := NewRootCommandWithApp(app)
	del.SetArgs([]string{"store", "ref-delete", "registry.example/team/test:1.0.0", refRec.Digest + "bad", "--yes"})
	if err := del.Execute(); err == nil || !application.IsKind(err, "repository") {
		t.Fatalf("CAS delete error=%v", err)
	}
}

func TestAppCommandsRejectUnboundAndMismatchedResolvers(t *testing.T) {
	dataA := t.TempDir()
	repoA := repository.Repository{Root: filepath.Join(dataA, "repository-v1")}
	if err := os.MkdirAll(repoA.Root, 0700); err != nil {
		t.Fatal(err)
	}
	repoB := repository.Repository{Root: t.TempDir()}
	t.Setenv("ADVERSARY_DATA_DIR", dataA)
	t.Setenv("HOME", dataA)
	ref := "registry.example/team/tool:1.0.0"
	for _, item := range []struct {
		repo repository.Repository
		body string
	}{{repoA, "a"}, {repoB, "b"}} {
		project := t.TempDir()
		writeProject(t, project)
		if err := os.WriteFile(filepath.Join(project, "dist", "index.js"), []byte(item.body), 0644); err != nil {
			t.Fatal(err)
		}
		a, err := pack.Create(context.Background(), pack.Options{Dir: project})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := item.repo.ImportPacked(a, ref); err != nil {
			t.Fatal(err)
		}
	}
	var out, errOut bytes.Buffer
	base := lifecycleTestApp(t, repoB, &out, &errOut).Dependencies()
	for _, tc := range []struct {
		name     string
		resolver application.Resolver
	}{{"generic", injectedResolver{}}, {"mismatch", processResolver{resolver: internaladversary.Resolver{Repository: repoA}}}} {
		t.Run(tc.name, func(t *testing.T) {
			deps := base
			deps.Resolver = tc.resolver
			app, err := application.New(deps)
			if err != nil {
				t.Fatal(err)
			}
			for _, args := range [][]string{{"run", "registry.example/team/tool:1.0.0"}, {"inspect", "registry.example/team/tool:1.0.0"}} {
				cmd := NewRootCommandWithApp(app)
				cmd.SetArgs(args)
				err := cmd.Execute()
				if err == nil || !application.IsKind(err, "invalid-dependency") {
					t.Fatalf("args=%v err=%v", args, err)
				}
			}
			if _, err := os.Stat(filepath.Join(repoB.Root, "materialized")); err == nil {
				entries, _ := os.ReadDir(filepath.Join(repoB.Root, "materialized"))
				if len(entries) > 0 {
					t.Fatal("invalid App materialized an artifact")
				}
			}
		})
	}
}
