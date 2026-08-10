package pipeline

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/adversarylabs/adversary/internal/train/adversaries"
	"github.com/adversarylabs/adversary/internal/train/cases"
	"github.com/adversarylabs/adversary/internal/train/receipt"
	"github.com/adversarylabs/adversary/internal/train/results"
)

func TestResolvePrimaryAdversaryName(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		opts Options
		pkgs []adversaries.Package
		want string
	}{
		{
			name: "explicit name wins",
			opts: Options{AdversaryName: "go-concurrency"},
			pkgs: []adversaries.Package{{ID: "engineering-review"}},
			want: "go-concurrency",
		},
		{
			name: "single loaded package",
			opts: Options{},
			pkgs: []adversaries.Package{{ID: "go-concurrency"}},
			want: "go-concurrency",
		},
		{
			name: "multi packages joined",
			opts: Options{},
			pkgs: []adversaries.Package{{ID: "go-testing"}, {ID: "go-concurrency"}},
			want: "go-concurrency+go-testing",
		},
		{
			name: "source path basename",
			opts: Options{AdversarySource: "/tmp/go-concurrency-adversary"},
			want: "go-concurrency",
		},
		{
			name: "local package dir basename",
			opts: Options{LocalPackageDirs: []string{"../go-concurrency-adversary"}},
			want: "go-concurrency",
		},
		{
			name: "legacy default",
			opts: Options{},
			want: "engineering-review",
		},
		{
			name: "train-only single",
			opts: Options{TrainOnlyIDs: []string{"go-security-adversary"}},
			pkgs: []adversaries.Package{{ID: "go-security"}, {ID: "go-concurrency"}},
			want: "go-security",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolvePrimaryAdversaryName(tc.opts, tc.pkgs)
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestPackageIDFromName(t *testing.T) {
	t.Parallel()
	if got := packageIDFromName("go-concurrency-adversary"); got != "go-concurrency" {
		t.Fatalf("got %q", got)
	}
	if got := packageIDFromName("/x/y/go-concurrency-adversary/"); got != "go-concurrency" {
		t.Fatalf("got %q", got)
	}
}

func TestGradeOwnersRunsOnlyRoutedPackages(t *testing.T) {
	if owners := gradeOwners(&cases.Case{}, "engineering-review"); len(owners) != 0 {
		t.Fatalf("empty-gold case should run no packages: %#v", owners)
	}
	c := &cases.Case{Labels: cases.Labels{ExpectedConcerns: []cases.ExpectedConcern{
		{ID: "one", Summary: "one", Approved: true, Scope: "in_scope", OwnerAdversary: "terraform"},
		{ID: "two", Summary: "two", Approved: true, Scope: "in_scope", OwnerAdversary: "terraform"},
		{ID: "three", Summary: "three", Approved: true, Scope: "in_scope", OwnerAdversary: "nits"},
		{ID: "ignored", Summary: "ignored", Approved: true, Scope: "out_of_scope", OwnerAdversary: "engineering-review"},
	}}}
	owners := gradeOwners(c, "engineering-review")
	if len(owners) != 2 || len(owners["terraform"]) != 2 || len(owners["nits"]) != 1 {
		t.Fatalf("grade owners = %#v", owners)
	}
	if _, ok := owners["engineering-review"]; ok {
		t.Fatalf("unrouted package must not run: %#v", owners)
	}
}

func TestCaseForGradedOwnersExcludesBlockedGold(t *testing.T) {
	c := &cases.Case{Labels: cases.Labels{ExpectedConcerns: []cases.ExpectedConcern{
		{ID: "nits", Approved: true, OwnerAdversary: "nits"},
		{ID: "tests", Approved: true, OwnerAdversary: "go-testing"},
		{ID: "fallback", Approved: true},
		{ID: "ignored", Approved: false, OwnerAdversary: "nits"},
	}}}
	got := caseForGradedOwners(c, map[string]bool{"nits": true, "engineering-review": true}, "engineering-review")
	if got == c {
		t.Fatal("expected a cloned case")
	}
	want := map[string]bool{"nits": true, "fallback": true, "ignored": true}
	if len(got.Labels.ExpectedConcerns) != len(want) {
		t.Fatalf("labels=%#v", got.Labels.ExpectedConcerns)
	}
	for _, label := range got.Labels.ExpectedConcerns {
		if !want[label.ID] {
			t.Fatalf("blocked owner's gold remained gradeable: %#v", label)
		}
	}
	if len(c.Labels.ExpectedConcerns) != 4 {
		t.Fatal("source case was mutated")
	}
}

func TestEligiblePriorMissRejectsLegacyConversationNoise(t *testing.T) {
	base := results.Result{
		Kind:    results.KindMiss,
		Status:  results.StatusNew,
		PRURL:   "https://github.com/acme/project/pull/1",
		Summary: "The parser accepts an invalid empty identifier.",
	}
	if !eligiblePriorMiss(base) {
		t.Fatal("actionable historical miss should remain eligible")
	}
	for _, summary := range []string{
		"Fixed in 5fbd67d.",
		"Overall: this is a correct, behavior-preserving cleanup.",
		"We don't need to worry because this is working as intended.",
	} {
		row := base
		row.Summary = summary
		if eligiblePriorMiss(row) {
			t.Errorf("legacy conversation noise remained eligible: %q", summary)
		}
	}
}

func TestTrainDraftContextMergesPackageIDs(t *testing.T) {
	t.Parallel()
	// CLI used to pass directory basename (…-adversary); drafts must still match short id.
	loc, off := trainDraftContext(Options{
		LocalIDs: []string{"go-concurrency-adversary"},
	}, []adversaries.Package{{ID: "go-concurrency", DirName: "go-concurrency-adversary"}})
	if !loc["go-concurrency"] {
		t.Fatalf("expected go-concurrency local, got %#v", loc)
	}
	if len(off) != 0 {
		t.Fatalf("unexpected official %#v", off)
	}
}

func TestFixtureSliceEndToEnd(t *testing.T) {
	// Locate repo root (module root with fixtures).
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// internal/train/pipeline -> internal/train (fixtures live here)
	repoRoot := filepath.Clean(filepath.Join(wd, ".."))
	if _, err := os.Stat(filepath.Join(repoRoot, "fixtures", "cases")); err != nil {
		t.Fatalf("fixtures not found at %s: %v", repoRoot, err)
	}
	dataRoot := t.TempDir()
	// Point source at sibling engineering-review if present (optional).
	src := filepath.Join(filepath.Dir(repoRoot), "engineering-review-adversary")
	if _, err := os.Stat(src); err != nil {
		src = ""
	}
	res, err := Run(Options{
		DataRoot:        dataRoot,
		RepoRoot:        repoRoot,
		Fixture:         true,
		AdversarySource: src,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Scorecard == nil {
		t.Fatal("missing scorecard")
	}
	if res.Scorecard.FailureCount < 1 {
		t.Fatalf("expected failures, got %d", res.Scorecard.FailureCount)
	}
	if len(res.Hypotheses) < 1 {
		t.Fatal("expected critic hypotheses")
	}
	if res.Proposal == nil || res.Proposal.PatchPath == "" {
		t.Fatal("expected optimizer proposal with patch")
	}
	if _, err := os.Stat(res.Proposal.PatchPath); err != nil {
		t.Fatal(err)
	}
	if res.Report == nil {
		t.Fatal("missing experiment report")
	}
	if res.Report.Decision != "" {
		t.Fatalf("decision must be human-unset, got %q", res.Report.Decision)
	}
	if res.Report.Status != "needs-human-review" {
		t.Fatalf("status=%s", res.Report.Status)
	}
	// Candidate scores must not fabricate improvement when not remeasured.
	switch res.Report.CandidateScoresMode {
	case "identical_to_base":
		if res.Report.OriginatingImproved || res.Report.DeltaRecall != 0 || res.Report.DeltaPrecision != 0 {
			t.Fatalf("identical_to_base invented improvement: improved=%v dRecall=%v dPrec=%v",
				res.Report.OriginatingImproved, res.Report.DeltaRecall, res.Report.DeltaPrecision)
		}
	case "remeasured":
		// deltas may be non-zero only from real re-judge
	default:
		t.Fatalf("unexpected candidate_scores_mode %q", res.Report.CandidateScoresMode)
	}
	// Receipt present and verifiable
	rpath := filepath.Join(dataRoot, "runs", res.RunID, "receipt.json")
	raw, err := os.ReadFile(rpath)
	if err != nil {
		t.Fatal(err)
	}
	var rcpt receipt.Receipt
	if err := json.Unmarshal(raw, &rcpt); err != nil {
		t.Fatal(err)
	}
	if err := receipt.Verify(&rcpt); err != nil {
		t.Fatal(err)
	}
	if rcpt.FinalStatus != "success" && rcpt.FinalStatus != "partial" {
		t.Fatalf("final_status=%s", rcpt.FinalStatus)
	}
	// No auto-merge markers
	if rcpt.Notes != "" && (contains(rcpt.Notes, "merged") || contains(rcpt.Notes, "published")) {
		t.Fatalf("unexpected merge/publish notes: %s", rcpt.Notes)
	}
	// Scorecard artifact
	if _, err := os.Stat(filepath.Join(dataRoot, "runs", res.RunID, "reports", "scorecard.json")); err != nil {
		t.Fatal(err)
	}
	// Human-readable story report
	if res.HumanReport == nil || res.HumanReport.READMEPath == "" {
		t.Fatal("expected human report path")
	}
	story, err := os.ReadFile(res.HumanReport.READMEPath)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(string(story), "Bottom line") || !contains(string(story), "What the human reviewer said") {
		t.Fatalf("story incomplete: %s", res.HumanReport.READMEPath)
	}
	if res.HumanReport.Verdict != "GOOD" && res.HumanReport.Verdict != "MIXED" && res.HumanReport.Verdict != "BAD" {
		t.Fatalf("unexpected verdict %q", res.HumanReport.Verdict)
	}
	if !contains(res.Message, "BOTTOM LINE") {
		t.Fatalf("CLI message should be plain English, got: %s", res.Message)
	}
	// Projection isolation already unit-tested; ensure materialized reviewer dir has no labels
	mat := filepath.Join(dataRoot, "runs", res.RunID, "materialized")
	_ = filepath.Walk(mat, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		b, _ := os.ReadFile(path)
		s := string(b)
		if contains(s, "expected_concerns") || contains(s, "c-leak-1") {
			t.Errorf("label leak in materialized %s", path)
		}
		return nil
	})
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		(len(s) > 0 && (stringIndex(s, sub) >= 0)))
}

func stringIndex(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
