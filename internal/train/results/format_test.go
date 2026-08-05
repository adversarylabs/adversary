package results

import "testing"

func TestKindNormalizeAndExplain(t *testing.T) {
	if normalizeKind("gold") != KindHuman {
		t.Fatal(normalizeKind("gold"))
	}
	if normalizeKind("extra") != KindFalsePositive {
		t.Fatal()
	}
	if KindLabel(KindMiss) != "miss" {
		t.Fatal(KindLabel(KindMiss))
	}
	s := KindExplain(KindMiss, StatusNew)
	if s == "" {
		t.Fatal("empty explain")
	}
	s = KindExplain(KindHuman, StatusCaught)
	if s == "" {
		t.Fatal()
	}
	table := FormatListTable(nil)
	if table == "" {
		t.Fatal()
	}
	table = FormatListTable([]Result{{
		ID: "abc", Status: StatusNew, Package: "go-concurrency",
		Kind: KindMiss, Summary: "leak",
	}})
	if table == "" {
		t.Fatal()
	}
	insp := FormatInspect(Result{ID: "x", Kind: KindDraft, Status: StatusNew, Summary: "s", DraftBody: "body"})
	if insp == "" {
		t.Fatal()
	}
}

func TestPackageIDHelpers(t *testing.T) {
	if packageFromLabels([]string{"adversary:go-concurrency"}) != "go-concurrency" {
		t.Fatal()
	}
	if packageFromTitle("go-concurrency: fix races") != "go-concurrency" {
		t.Fatal()
	}
	if soft("hello", 100) != "hello" {
		t.Fatal()
	}
	if trunc("abcdef", 4) != "abc…" {
		t.Fatal(trunc("abcdef", 4))
	}
}
