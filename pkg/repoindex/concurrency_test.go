package repoindex

import (
	"fmt"
	"sync"
	"testing"
)

func TestEnsureConcurrentSameRepository(t *testing.T) {
	root := concurrentTestRepository(t)
	t.Setenv("ADVERSARY_REPO_INDEX_DIR", t.TempDir())

	runConcurrentEnsures(t, 12, func() error {
		_, err := Ensure(root, ModeAuto, nil)
		return err
	})

	handle, err := Ensure(root, ModeAuto, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !filesExist(handle.Dir) {
		t.Fatalf("concurrent build did not publish a complete v1 index at %s", handle.Dir)
	}
}

func TestEnsureV2ConcurrentSameRepository(t *testing.T) {
	root := concurrentTestRepository(t)
	t.Setenv("ADVERSARY_REPO_INDEX_DIR", t.TempDir())

	runConcurrentEnsures(t, 12, func() error {
		_, err := EnsureV2(root, ModeAuto, nil)
		return err
	})

	handle, err := EnsureV2(root, ModeAuto, nil)
	if err != nil {
		t.Fatal(err)
	}
	graph, err := OpenV2(handle.Dir)
	if err != nil {
		t.Fatalf("concurrent build did not publish a readable v2 index: %v", err)
	}
	if err := graph.Close(); err != nil {
		t.Fatal(err)
	}
}

func concurrentTestRepository(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	run(t, root, "git", "init")
	run(t, root, "git", "config", "user.email", "t@example.com")
	run(t, root, "git", "config", "user.name", "t")
	write(t, root, "go.mod", "module example.com/concurrent\n\ngo 1.22\n")
	for i := 0; i < 24; i++ {
		write(t, root, fmt.Sprintf("pkg/p%d/p.go", i), fmt.Sprintf("package p%d\n\nfunc Value() int { return %d }\n", i, i))
	}
	run(t, root, "git", "add", ".")
	run(t, root, "git", "commit", "-m", "init")
	return root
}

func runConcurrentEnsures(t *testing.T, count int, ensure func() error) {
	t.Helper()
	start := make(chan struct{})
	errs := make(chan error, count)
	var ready sync.WaitGroup
	ready.Add(count)
	for i := 0; i < count; i++ {
		go func() {
			ready.Done()
			<-start
			errs <- ensure()
		}()
	}
	ready.Wait()
	close(start)
	for i := 0; i < count; i++ {
		if err := <-errs; err != nil {
			t.Errorf("concurrent ensure failed: %v", err)
		}
	}
}
