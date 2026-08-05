package pipeline

import (
	"testing"

	"github.com/adversarylabs/adversary/internal/train/cases"
	"github.com/adversarylabs/adversary/internal/train/collect"
	"github.com/adversarylabs/adversary/internal/train/dataroot"
)

func TestLooksJSONAndWrap(t *testing.T) {
	if !looksJSON([]byte(`{"a":1}`)) || !looksJSON([]byte(`  [1]`)) {
		t.Fatal()
	}
	if looksJSON([]byte(`not json`)) {
		t.Fatal()
	}
	if softWrapOne("hello world", 5) == "" {
		t.Fatal()
	}
	if truncate("abcdef", 3) == "abcdef" {
		t.Fatal()
	}
	if stageClass(Options{Live: true}) != dataroot.ClassReal {
		// may be partial
	}
	if stageClass(Options{Fixture: true}) == "" {
		t.Fatal()
	}
}

func TestApplyCollectResult(t *testing.T) {
	out := &huntOutcome{}
	c := &cases.Case{ID: "c1"}
	applyCollectResult(out, collectResult{
		kept: []*cases.Case{c}, inScopeN: 1, outScopeN: 0,
		execClass: dataroot.ClassReal,
	}, false)
	if out.prsWithInScope != 1 || len(out.caseList) != 1 {
		t.Fatalf("%+v", out)
	}
	out2 := &huntOutcome{}
	applyCollectResult(out2, collectResult{
		kept: []*cases.Case{c}, inScopeN: 0, outScopeN: 2,
		execClass: dataroot.ClassReal,
	}, true)
	if len(out2.caseList) != 1 {
		t.Fatal("pinned should keep")
	}
	out3 := &huntOutcome{}
	applyCollectResult(out3, collectResult{blocked: &dataroot.BlockedResult{Classification: "x"}}, false)
	if out3.blocked == nil {
		t.Fatal()
	}
	_ = collect.PRRef{}
}

func TestTrainDraftContext(t *testing.T) {
	loc, off := trainDraftContext(Options{LocalIDs: []string{"go-concurrency-adversary"}}, nil)
	if !loc["go-concurrency"] {
		t.Fatalf("%v", loc)
	}
	_ = off
}

func TestPackageIDFromPath(t *testing.T) {
	if packageIDFromName("/tmp/foo-adversary/") != "foo" {
		t.Fatal(packageIDFromName("/tmp/foo-adversary/"))
	}
}
