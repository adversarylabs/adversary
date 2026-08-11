package state

import (
	"sync"
	"testing"
)

func TestTakeCatalogWindowRotatesAndWraps(t *testing.T) {
	dir := t.TempDir()

	start, count, err := TakeCatalogWindow(dir, "typescript", 12, 5)
	if err != nil {
		t.Fatal(err)
	}
	if start != 0 || count != 5 {
		t.Fatalf("first window = (%d, %d), want (0, 5)", start, count)
	}

	start, count, err = TakeCatalogWindow(dir, "typescript", 12, 5)
	if err != nil {
		t.Fatal(err)
	}
	if start != 5 || count != 5 {
		t.Fatalf("second window = (%d, %d), want (5, 5)", start, count)
	}

	start, count, err = TakeCatalogWindow(dir, "typescript", 12, 5)
	if err != nil {
		t.Fatal(err)
	}
	if start != 10 || count != 2 {
		t.Fatalf("tail window = (%d, %d), want (10, 2)", start, count)
	}

	start, count, err = TakeCatalogWindow(dir, "typescript", 12, 5)
	if err != nil {
		t.Fatal(err)
	}
	if start != 0 || count != 5 {
		t.Fatalf("post-wrap window = (%d, %d), want (0, 5)", start, count)
	}
}

func TestTakeCatalogWindowSeedsNewTargetsAndClamps(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := TakeCatalogWindow(dir, "first", 10, 3); err != nil {
		t.Fatal(err)
	}
	start, count, err := TakeCatalogWindow(dir, "second", 10, 20)
	if err != nil {
		t.Fatal(err)
	}
	if start != 3 || count != 7 {
		t.Fatalf("seeded window = (%d, %d), want (3, 7)", start, count)
	}
}

func TestTakeCatalogWindowEveryTargetCoversEntireCatalog(t *testing.T) {
	dir := t.TempDir()
	for _, target := range []string{"a", "b", "c", "d", "e", "f", "g"} {
		covered := map[int]bool{}
		for len(covered) < 279 {
			start, count, err := TakeCatalogWindow(dir, target, 279, 50)
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < count; i++ {
				covered[start+i] = true
			}
		}
		if len(covered) != 279 {
			t.Fatalf("target %q covered %d repositories, want 279", target, len(covered))
		}
	}
}

func TestTakeCatalogWindowConcurrentReservationsDoNotOverlap(t *testing.T) {
	dir := t.TempDir()
	const reservations = 10
	starts := make(chan int, reservations)
	errs := make(chan error, reservations)
	var wg sync.WaitGroup
	for range reservations {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start, _, err := TakeCatalogWindow(dir, "same-target", 100, 10)
			if err != nil {
				errs <- err
				return
			}
			starts <- start
		}()
	}
	wg.Wait()
	close(starts)
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	seen := map[int]bool{}
	for start := range starts {
		if seen[start] {
			t.Fatalf("duplicate reserved start %d", start)
		}
		seen[start] = true
	}
	if len(seen) != reservations {
		t.Fatalf("reserved %d distinct windows, want %d", len(seen), reservations)
	}
}
