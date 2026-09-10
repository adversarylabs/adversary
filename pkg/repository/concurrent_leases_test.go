package repository

import (
	"testing"
	"time"
)

func TestConcurrentRuntimeLeases(t *testing.T) {
	r := Repository{Root: t.TempDir()}
	t.Cleanup(func() { makeWritable(r.Root) })
	rec, err := r.ImportPacked(artifact(t, "one"), "")
	if err != nil {
		t.Fatal(err)
	}
	first, err := r.LeaseMaterialized(rec)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	type result struct {
		lease *MaterializationLease
		err   error
	}
	acquired := make(chan result, 1)
	go func() { lease, err := r.LeaseMaterialized(rec); acquired <- result{lease, err} }()
	select {
	case got := <-acquired:
		if got.err != nil {
			t.Fatal(got.err)
		}
		defer got.lease.Close()
		if got.lease.Path != first.Path {
			t.Fatal("leases disagree on immutable materialization")
		}
	case <-time.After(time.Second):
		// Release and join the waiter before failing; do not leave a blocked goroutine.
		first.Close()
		got := <-acquired
		if got.lease != nil {
			got.lease.Close()
		}
		t.Fatal("second runtime lease serialized behind the first active review")
	}
}

func TestGCWaitsForLastRuntimeLease(t *testing.T) {
	r := Repository{Root: t.TempDir()}
	t.Cleanup(func() { makeWritable(r.Root) })
	rec, err := r.ImportPacked(artifact(t, "one"), "")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := r.PlanGC()
	if err != nil {
		t.Fatal(err)
	}
	first, err := r.LeaseMaterialized(rec)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := r.LeaseMaterialized(rec)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	done := make(chan error, 1)
	go func() { _, err := r.ApplyGC(plan, false); done <- err }()
	first.Close()
	select {
	case err := <-done:
		t.Fatalf("GC completed while second runtime lease remained: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("GC did not resume after last lease closed")
	}
}
