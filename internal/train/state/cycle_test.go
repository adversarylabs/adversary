package state

import "testing"

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
