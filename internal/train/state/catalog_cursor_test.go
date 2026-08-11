package state

import (
	"sync"
	"testing"
)

func TestTakeCatalogWindowRotatesAndWraps(t *testing.T) {
	dir := t.TempDir()

	start, count, err := TakeCatalogWindow(dir, 12, 5, false)
	if err != nil {
		t.Fatal(err)
	}
	if start != 0 || count != 5 {
		t.Fatalf("first window = (%d, %d), want (0, 5)", start, count)
	}

	start, count, err = TakeCatalogWindow(dir, 12, 5, false)
	if err != nil {
		t.Fatal(err)
	}
	if start != 5 || count != 5 {
		t.Fatalf("second window = (%d, %d), want (5, 5)", start, count)
	}

	start, count, err = TakeCatalogWindow(dir, 12, 5, false)
	if err != nil {
		t.Fatal(err)
	}
	if start != 10 || count != 2 {
		t.Fatalf("tail window = (%d, %d), want (10, 2)", start, count)
	}

	start, count, err = TakeCatalogWindow(dir, 12, 5, false)
	if err != nil {
		t.Fatal(err)
	}
	if start != 0 || count != 5 {
		t.Fatalf("post-wrap window = (%d, %d), want (0, 5)", start, count)
	}
}

func TestTakeCatalogWindowResetAndClamp(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := TakeCatalogWindow(dir, 4, 2, false); err != nil {
		t.Fatal(err)
	}
	start, count, err := TakeCatalogWindow(dir, 4, 20, true)
	if err != nil {
		t.Fatal(err)
	}
	if start != 0 || count != 4 {
		t.Fatalf("reset window = (%d, %d), want (0, 4)", start, count)
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
			start, _, err := TakeCatalogWindow(dir, 100, 10, false)
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
