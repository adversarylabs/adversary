package state

import (
	"path/filepath"
	"testing"
)

func TestDiscoveryStoreSkipAndPersist(t *testing.T) {
	dir := t.TempDir()
	s, err := LoadDiscovery(dir, "open-telemetry", "opentelemetry-go")
	if err != nil {
		t.Fatal(err)
	}
	if s.Seen(8685) {
		t.Fatal("should not be seen yet")
	}
	s.Record(8685, "title", "https://example/pull/8685", OutcomeNoInScope, "docs only")
	if !s.Seen(8685) {
		t.Fatal("should be seen")
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	path := PathFor(dir, "open-telemetry", "opentelemetry-go")
	if _, err := filepath.Abs(path); err != nil {
		t.Fatal(err)
	}
	s2, err := LoadDiscovery(dir, "open-telemetry", "opentelemetry-go")
	if err != nil {
		t.Fatal(err)
	}
	if !s2.Seen(8685) {
		t.Fatal("reload should remember 8685")
	}
	if s2.PRs["8685"].Outcome != OutcomeNoInScope {
		t.Fatalf("outcome=%s", s2.PRs["8685"].Outcome)
	}
	if s2.PRs["8685"].Attempts != 1 {
		t.Fatalf("attempts=%d", s2.PRs["8685"].Attempts)
	}
}

func TestTargetDiscoveryStoresAreIsolated(t *testing.T) {
	dir := t.TempDir()
	first, err := LoadDiscoveryForTarget(dir, "go-testing", "owner", "repo")
	if err != nil {
		t.Fatal(err)
	}
	first.Record(42, "title", "url", OutcomeNoInScope, "not testing")
	if err := first.Save(); err != nil {
		t.Fatal(err)
	}
	second, err := LoadDiscoveryForTarget(dir, "go-security", "owner", "repo")
	if err != nil {
		t.Fatal(err)
	}
	if second.Seen(42) {
		t.Fatal("PR seen by one target leaked into another target's discovery state")
	}
}
