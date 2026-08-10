package pipeline

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/adversarylabs/adversary/internal/train/cases"
	"github.com/adversarylabs/adversary/internal/train/runner"
	"github.com/adversarylabs/adversary/internal/train/state"
)

func TestNormalizeConcurrency(t *testing.T) {
	t.Parallel()
	if got := normalizeConcurrency(0); got != defaultHuntConcurrency {
		t.Fatalf("default: got %d", got)
	}
	if got := normalizeConcurrency(-1); got != defaultHuntConcurrency {
		t.Fatalf("neg: got %d", got)
	}
	if got := normalizeConcurrency(3); got != 3 {
		t.Fatalf("3: got %d", got)
	}
	if got := normalizeConcurrency(100); got != maxHuntConcurrency {
		t.Fatalf("cap: got %d", got)
	}
}

func TestDiscoveryStoreConcurrentRecord(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s, err := state.LoadDiscovery(dir, "o", "r")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 1; i <= 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			s.Record(n, "t", "u", state.OutcomeNoInScope, "note")
			_ = s.Save()
			_ = s.Seen(n)
			_ = s.SeenSet()
		}(i)
	}
	wg.Wait()
	if len(s.ListNumbers()) != 50 {
		t.Fatalf("want 50 records, got %d", len(s.ListNumbers()))
	}
}

func TestLockLocalPackageSerializes(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	var order []int
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			unlock := runner.LockLocalPackage(dir)
			mu.Lock()
			order = append(order, id)
			mu.Unlock()
			time.Sleep(30 * time.Millisecond)
			mu.Lock()
			order = append(order, id+10)
			mu.Unlock()
			unlock()
		}(i)
	}
	wg.Wait()
	// Fully nested: first complete (id, id+10) before second starts.
	if len(order) != 4 {
		t.Fatalf("order %#v", order)
	}
	// First two entries must be same id and id+10 (serialized).
	if order[1] != order[0]+10 {
		t.Fatalf("not serialized: %#v", order)
	}
	if order[3] != order[2]+10 {
		t.Fatalf("not serialized: %#v", order)
	}
}

func TestApplyCollectResultPinned(t *testing.T) {
	t.Parallel()
	out := &huntOutcome{}
	c := &cases.Case{ID: "c1"}
	applyCollectResult(out, collectResult{kept: []*cases.Case{c}, inScopeN: 0}, true, 1)
	if len(out.caseList) != 1 {
		t.Fatalf("pinned empty gold should still keep case")
	}
	out2 := &huntOutcome{}
	applyCollectResult(out2, collectResult{kept: []*cases.Case{c}, inScopeN: 1}, false, 1)
	if out2.prsWithInScope != 1 {
		t.Fatalf("in-scope count")
	}
}

func TestApplyCollectResultEnforcesTargetSequentially(t *testing.T) {
	t.Parallel()
	out := &huntOutcome{}
	persisted := 0
	for i := 0; i < 5; i++ {
		c := &cases.Case{ID: fmt.Sprintf("c%d", i)}
		if applyCollectResult(out, collectResult{kept: []*cases.Case{c}, inScopeN: 1}, false, 1) {
			persisted++
		}
	}
	if out.prsWithInScope != 1 || len(out.caseList) != 1 || persisted != 1 {
		t.Fatalf("cap not enforced: prs=%d cases=%d persisted=%d", out.prsWithInScope, len(out.caseList), persisted)
	}
}

func TestApplyCollectResultEnforcesTargetConcurrently(t *testing.T) {
	t.Parallel()
	out := &huntOutcome{}
	var mu sync.Mutex
	persisted := 0
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c := &cases.Case{ID: fmt.Sprintf("c%d", i)}
			mu.Lock()
			if applyCollectResult(out, collectResult{kept: []*cases.Case{c}, inScopeN: 1}, false, 1) {
				persisted++
			}
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	if out.prsWithInScope != 1 || len(out.caseList) != 1 || persisted != 1 {
		t.Fatalf("cap not enforced: prs=%d cases=%d persisted=%d", out.prsWithInScope, len(out.caseList), persisted)
	}
}
