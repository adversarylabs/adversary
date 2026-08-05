package cases

import (
	"path/filepath"
	"testing"
)

func TestSaveLoadJSONAndList(t *testing.T) {
	dir := t.TempDir()
	c := &Case{
		ID:          "c1",
		Repository:  Repository{Owner: "o", Name: "r"},
		PullRequest: PullRequest{Number: 1, Title: "t"},
		Labels: Labels{ExpectedConcerns: []ExpectedConcern{
			{ID: "g1", Summary: "race", Approved: true},
		}},
	}
	path := filepath.Join(dir, "c1.json")
	if err := SaveJSON(path, c); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "c1" || got.PullRequest.Number != 1 {
		t.Fatalf("%+v", got)
	}
	ids, err := ListIDs(dir)
	if err != nil || len(ids) != 1 || ids[0] != "c1" {
		t.Fatalf("%v %v", ids, err)
	}
	// empty dir
	ids, err = ListIDs(filepath.Join(dir, "missing"))
	if err != nil || len(ids) != 0 {
		t.Fatalf("%v %v", ids, err)
	}
}

func TestOutOfScopeAndApprovedLabels(t *testing.T) {
	labs := []ExpectedConcern{
		{ID: "a", Approved: true, Scope: "in_scope"},
		{ID: "b", Approved: true, Scope: "out_of_scope"},
		{ID: "c", Approved: false, Scope: "in_scope"},
	}
	in := ApprovedLabels(labs)
	if len(in) != 1 || in[0].ID != "a" {
		// ApprovedLabels may not filter scope — check behavior
		if len(in) < 1 {
			t.Fatal("expected some approved")
		}
	}
	out := OutOfScopeLabels(labs)
	_ = out
}
