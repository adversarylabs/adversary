package state

import (
	"fmt"
	"sync"
	"testing"
)

func TestAdversaryCycleVisitsEveryTargetBeforeRepeating(t *testing.T) {
	dir := t.TempDir()
	cycle, err := LoadAdversaryCycle(dir)
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{"go-testing", "engineering-review", "go-concurrency"}
	want := []string{"engineering-review", "go-concurrency", "go-testing", "engineering-review"}
	for i, expected := range want {
		got, err := cycle.Select(ids, "run")
		if err != nil {
			t.Fatal(err)
		}
		if got != expected {
			t.Fatalf("selection %d: got %q want %q", i, got, expected)
		}
	}
}

func TestAdversaryCyclePersistsAndPrioritizesNewTarget(t *testing.T) {
	dir := t.TempDir()
	cycle, err := LoadAdversaryCycle(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cycle.Select([]string{"a", "b"}, "run-1"); err != nil {
		t.Fatal(err)
	}
	reloaded, err := LoadAdversaryCycle(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := reloaded.Peek([]string{"a", "b", "new"}); got != "b" {
		// b and new are both unseen; stable lexical order keeps scheduling deterministic.
		t.Fatalf("got %q want b", got)
	}
	if _, err := reloaded.Select([]string{"a", "b"}, "run-2"); err != nil {
		t.Fatal(err)
	}
	if got := reloaded.Peek([]string{"a", "b", "new"}); got != "new" {
		t.Fatalf("new target was not prioritized, got %q", got)
	}
}

func TestAdversaryCycleConcurrentSelectionsAreNotLost(t *testing.T) {
	dir := t.TempDir()
	ids := []string{"a", "b", "c"}
	var wg sync.WaitGroup
	errs := make(chan error, 30)
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cycle, err := LoadAdversaryCycle(dir)
			if err != nil {
				errs <- err
				return
			}
			if _, err := cycle.Select(ids, fmt.Sprintf("run-%d", i)); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	cycle, err := LoadAdversaryCycle(dir)
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, id := range ids {
		total += cycle.Targets[id].Selections
		if cycle.Targets[id].Selections != 10 {
			t.Fatalf("target %s selections=%d want 10", id, cycle.Targets[id].Selections)
		}
	}
	if total != 30 {
		t.Fatalf("selection total=%d want 30", total)
	}
}
