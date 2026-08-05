package results

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/adversarylabs/adversary/internal/train/cases"
	"github.com/adversarylabs/adversary/internal/train/judge"
	"github.com/adversarylabs/adversary/internal/train/report"
)

func TestSQLiteWriteListInspectApply(t *testing.T) {
	state := t.TempDir()
	n, err := WriteFromRun(state, WriteInput{
		RunID: "slice-test",
		Cases: []*cases.Case{{
			ID: "c1",
			Repository: cases.Repository{Owner: "o", Name: "r", URL: "https://github.com/o/r"},
			PullRequest: cases.PullRequest{Number: 1, Title: "fix leak"},
			Labels: cases.Labels{ExpectedConcerns: []cases.ExpectedConcern{
				{ID: "g1", Summary: "goroutine leak on Shutdown", Approved: true, OwnerAdversary: "go-concurrency"},
			}},
		}},
		Failures: []judge.Failure{
			{CaseID: "c1", Kind: "missed-concern", ConcernID: "g1", ReviewerID: "go-concurrency"},
		},
		Issues: []report.SuggestedIssue{
			{
				Title:  "go-concurrency: catch lifecycle misses",
				Labels: []string{"train", "adversary:go-concurrency", "miss"},
				Body:   "Improve shutdown detection.\n",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Fatalf("expected results, got %d", n)
	}
	if _, err := os.Stat(DBPath(state)); err != nil {
		t.Fatalf("expected results.db: %v", err)
	}

	rows, err := List(state, "", "new")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) < 1 {
		t.Fatal("list empty")
	}
	table := FormatListTable(rows)
	if !strings.Contains(table, "go-concurrency") {
		t.Fatalf("table: %s", table)
	}
	if !strings.Contains(table, "SQLite") {
		t.Fatalf("should mention SQLite store: %s", table)
	}

	id := rows[0].ID
	got, err := Get(state, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Package == "" && got.Summary == "" {
		t.Fatalf("empty result: %+v", got)
	}

	// idempotent write
	n2, err := WriteFromRun(state, WriteInput{
		RunID: "slice-test",
		Issues: []report.SuggestedIssue{{
			Title:  "go-concurrency: catch lifecycle misses",
			Labels: []string{"train", "adversary:go-concurrency", "miss"},
			Body:   "Improve shutdown detection.\n",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if n2 != 0 {
		t.Fatalf("expected 0 new on re-write, got %d", n2)
	}

	pkg := t.TempDir()
	_ = os.MkdirAll(filepath.Join(pkg, "docs"), 0o755)
	ar, err := Apply(state, id, ApplyOptions{PackagePath: pkg, CreateBranch: false})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(ar.Path); err != nil {
		t.Fatal(err)
	}
	got, err = Get(state, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusApplied {
		t.Fatalf("status %s", got.Status)
	}
}

func TestResetResultsClearsDB(t *testing.T) {
	state := t.TempDir()
	if err := SaveResult(state, Result{
		ID: "abc12345", RunID: "r1", Package: "go-concurrency",
		Kind: KindDraft, Status: StatusNew, Summary: "test",
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	n, err := ResetResults(state)
	if err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Fatalf("removed %d", n)
	}
	rows, err := List(state, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("still have %d", len(rows))
	}
}

func TestResetDiscovery(t *testing.T) {
	state := t.TempDir()
	dir := filepath.Join(state, "state", "discovery")
	_ = os.MkdirAll(dir, 0o755)
	_ = os.WriteFile(filepath.Join(dir, "o__r.json"), []byte(`{}`), 0o644)
	n, err := ResetDiscovery(state)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("removed %d", n)
	}
}

func TestProgressiveKeptThenGraded(t *testing.T) {
	state := t.TempDir()
	c := &cases.Case{
		ID: "c-prog",
		Repository: cases.Repository{Owner: "o", Name: "r", URL: "https://github.com/o/r"},
		PullRequest: cases.PullRequest{Number: 9, Title: "race fix"},
		Labels: cases.Labels{ExpectedConcerns: []cases.ExpectedConcern{
			{ID: "g1", Summary: "data race on map", Approved: true, OwnerAdversary: "go-concurrency"},
		}},
	}
	n, err := WriteKeptCase(state, "run-1", c)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("kept n=%d", n)
	}
	rows, _ := List(state, "", "new")
	if len(rows) != 1 || rows[0].Kind != KindHuman {
		t.Fatalf("want human row, got %+v", rows)
	}
	// Grade as miss
	n2, err := WriteGradedCase(state, "run-1", c, []judge.Failure{
		{CaseID: "c-prog", Kind: "missed-concern", ConcernID: "g1", ReviewerID: "go-concurrency"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if n2 < 1 {
		t.Fatalf("grade n=%d", n2)
	}
	got, err := Get(state, rows[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != KindMiss {
		t.Fatalf("want miss, got %s", got.Kind)
	}
	// Re-keep same gold must not duplicate
	n3, err := WriteKeptCase(state, "run-1", c)
	if err != nil {
		t.Fatal(err)
	}
	if n3 != 0 {
		t.Fatalf("dup keep n=%d", n3)
	}
	// Grade as caught
	c2 := &cases.Case{
		ID: "c-hit",
		Repository: cases.Repository{Owner: "o", Name: "r"},
		PullRequest: cases.PullRequest{Number: 2},
		Labels: cases.Labels{ExpectedConcerns: []cases.ExpectedConcern{
			{ID: "g2", Summary: "leak", Approved: true, OwnerAdversary: "go-concurrency"},
		}},
	}
	_, _ = WriteKeptCase(state, "run-1", c2)
	_, err = WriteGradedCase(state, "run-1", c2, nil) // no miss = caught
	if err != nil {
		t.Fatal(err)
	}
	rows2, _ := List(state, "go-concurrency", "caught")
	if len(rows2) < 1 {
		t.Fatal("expected caught status")
	}
}

func TestLegacyJSONMigration(t *testing.T) {
	state := t.TempDir()
	legacy := filepath.Join(state, "results")
	_ = os.MkdirAll(legacy, 0o755)
	r := Result{
		ID: "legacy01", RunID: "old", Package: "go-concurrency",
		Kind: KindDraft, Status: StatusNew, Summary: "from json",
		CreatedAt: time.Now().UTC(),
	}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(legacy, "legacy01.json"), raw, 0o644)
	idx, _ := json.Marshal(map[string]any{"schema_version": 1, "results": []Result{r}})
	_ = os.WriteFile(filepath.Join(legacy, "index.json"), idx, 0o644)

	got, err := Get(state, "legacy01")
	if err != nil {
		t.Fatal(err)
	}
	if got.Summary != "from json" {
		t.Fatalf("%+v", got)
	}
}
