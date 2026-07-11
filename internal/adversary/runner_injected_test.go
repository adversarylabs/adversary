package adversary

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/adversarylabs/adversary/pkg/repository"
)

type pathExecutor struct{ path string }

func (e *pathExecutor) Run(_ context.Context, s ContainerSpec) (ContainerResult, error) {
	e.path = s.AdversaryPath
	if err := os.WriteFile(filepath.Join(s.RunDir, "output.json"), minimalEnvelope(), 0644); err != nil {
		return ContainerResult{}, err
	}
	return ContainerResult{Kind: "Process"}, nil
}

type blockingPathExecutor struct{ started, release chan struct{} }
type exitExecutor struct{ err error }

func (e exitExecutor) Run(ctx context.Context, s ContainerSpec) (ContainerResult, error) {
	if e.err != nil {
		return ContainerResult{}, e.err
	}
	return ContainerResult{}, ctx.Err()
}

func TestRunnerReleasesLeaseOnErrorAndCancellation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cancel bool
		err    error
	}{{"error", false, errors.New("runtime failed")}, {"cancel", true, nil}} {
		t.Run(tc.name, func(t *testing.T) {
			repo := repository.Repository{Root: t.TempDir()}
			t.Cleanup(func() { makeResolverWritable(repo.Root) })
			rec, err := repo.ImportPacked(resolverArtifact(t, t.TempDir(), "team/tool", tc.name), "")
			if err != nil {
				t.Fatal(err)
			}
			resolver := Resolver{Repository: repo}
			ctx, cancel := context.WithCancel(context.Background())
			if tc.cancel {
				cancel()
			} else {
				defer cancel()
			}
			_ = Runner{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}, Executor: exitExecutor{err: tc.err}, Repository: &repo, Resolver: &resolver}.Run(ctx, RunOptions{AdversaryRef: rec.Digest, RepoPath: t.TempDir(), Format: "json"})
			plan, err := repo.PlanGC()
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { _, err := repo.ApplyGC(plan, false); done <- err }()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("GC blocked after runner exit")
			}
		})
	}
}

func (e *blockingPathExecutor) Run(_ context.Context, s ContainerSpec) (ContainerResult, error) {
	close(e.started)
	<-e.release
	if err := os.WriteFile(filepath.Join(s.RunDir, "output.json"), minimalEnvelope(), 0644); err != nil {
		return ContainerResult{}, err
	}
	return ContainerResult{Kind: "Process"}, nil
}

func TestRunnerLeaseBlocksGCUntilExecutorReturns(t *testing.T) {
	repo := repository.Repository{Root: t.TempDir()}
	t.Cleanup(func() { makeResolverWritable(repo.Root) })
	a := resolverArtifact(t, t.TempDir(), "team/tool", "run")
	rec, err := repo.ImportPacked(a, "")
	if err != nil {
		t.Fatal(err)
	}
	resolver := Resolver{Repository: repo}
	executor := &blockingPathExecutor{started: make(chan struct{}), release: make(chan struct{})}
	runDone := make(chan error, 1)
	go func() {
		runDone <- Runner{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}, Executor: executor, Repository: &repo, Resolver: &resolver}.Run(context.Background(), RunOptions{AdversaryRef: rec.Digest, RepoPath: t.TempDir(), Format: "json"})
	}()
	<-executor.started
	plan, err := repo.PlanGC()
	if err != nil {
		t.Fatal(err)
	}
	gcDone := make(chan error, 1)
	go func() { _, err := repo.ApplyGC(plan, false); gcDone <- err }()
	select {
	case err := <-gcDone:
		t.Fatalf("GC completed during run: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(executor.release)
	if err := <-runDone; err != nil {
		t.Fatal(err)
	}
	if err := <-gcDone; err != nil {
		t.Fatal(err)
	}
}

func TestRunnerUsesInjectedResolverAndRepositoryForLease(t *testing.T) {
	ref := "registry.example/team/tool:1.0.0"
	repoA := repository.Repository{Root: t.TempDir()}
	repoB := repository.Repository{Root: t.TempDir()}
	t.Cleanup(func() { makeResolverWritable(repoA.Root); makeResolverWritable(repoB.Root) })
	a := resolverArtifact(t, t.TempDir(), "team/tool", "a")
	b := resolverArtifact(t, t.TempDir(), "team/tool", "b")
	if _, err := repoA.ImportPacked(a, ref); err != nil {
		t.Fatal(err)
	}
	recB, err := repoB.ImportPacked(b, ref)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", filepath.Join(t.TempDir(), "must-not-be-used"))
	resolver := Resolver{Repository: repoB}
	executor := &pathExecutor{}
	var out bytes.Buffer
	err = Runner{Stdout: &out, Stderr: &bytes.Buffer{}, Executor: executor, Repository: &repoB, Resolver: &resolver}.Run(context.Background(), RunOptions{AdversaryRef: ref, RepoPath: t.TempDir(), Format: "json"})
	if err != nil {
		t.Fatal(err)
	}
	_ = recB
	wantPrefix := filepath.Join(repoB.Root, "materialized") + string(filepath.Separator)
	if !strings.HasPrefix(executor.path, wantPrefix) {
		t.Fatalf("executor path=%q want injected prefix %q", executor.path, wantPrefix)
	}
	if strings.HasPrefix(executor.path, repoA.Root+string(filepath.Separator)) {
		t.Fatal("other repository path executed")
	}
}
