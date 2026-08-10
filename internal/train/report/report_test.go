package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/adversarylabs/adversary/internal/train/cases"
	"github.com/adversarylabs/adversary/internal/train/experiment"
	"github.com/adversarylabs/adversary/internal/train/judge"
	"github.com/adversarylabs/adversary/internal/train/normalize"
	"github.com/adversarylabs/adversary/internal/train/score"
)

func TestWriteStoryIsPlainEnglish(t *testing.T) {
	dir := t.TempDir()
	runDir := filepath.Join(dir, "runs", "slice-test")
	expDir := filepath.Join(dir, "experiments", "slice-test")
	c := &cases.Case{
		ID: "opentelemetry-go-pr-9001-r1",
		Repository: cases.Repository{
			Owner: "open-telemetry", Name: "opentelemetry-go",
			URL: "https://github.com/open-telemetry/opentelemetry-go/pull/9001",
		},
		PullRequest: cases.PullRequest{Number: 9001, Title: "fix leak"},
		ReviewEvent: cases.ReviewEvent{ReviewedSHA: "bbb", Reviewers: []string{"alice"}},
		Comments: []cases.Comment{{
			ID: 20001, Author: "alice",
			Body: "This goroutine can leak after Shutdown if the context is not cancelled",
			Path: "sdk/trace/span_processor.go", Line: 142,
			GeneralizedConcern: "Worker goroutine lifecycle not tied to Shutdown",
			ApprovedAsLabel:    true,
		}},
		Labels: cases.Labels{ExpectedConcerns: []cases.ExpectedConcern{
			{ID: "c-leak-1", Summary: "Worker goroutine lifecycle not tied to Shutdown", File: "sdk/trace/span_processor.go", Approved: true, Importance: "high", OwnerAdversary: "engineering-review"},
			{ID: "c-miss", Summary: "Export errors ignored during shutdown", Approved: true, Importance: "high", OwnerAdversary: "engineering-review"},
		}},
		Metadata: cases.Metadata{CreatedAt: time.Now().UTC(), Split: "discovery"},
	}
	j := &judge.ReviewJudgment{
		ReviewerID: "engineering-review", ImportantRecall: 0.5, Precision: 0.5,
		ExpectedMatched: []string{"c-leak-1"}, ExpectedMissed: []string{"c-miss"},
		Findings: []judge.FindingJudgment{
			{FindingID: "er-1", MatchesExpectedConcern: "c-leak-1", Valid: true},
			{FindingID: "er-2", Valid: false},
		},
	}
	rev := &normalize.Review{
		ReviewerID: "engineering-review",
		Findings: []normalize.Finding{
			{ID: "er-1", Severity: "high", Claim: "worker may leak after shutdown", File: "sdk/trace/span_processor.go", LineStart: 142},
			{ID: "er-2", Severity: "info", Claim: "maybe the API is wrong somewhere"},
		},
	}
	sc := score.Aggregate("engineering-review", map[string]*judge.ReviewJudgment{c.ID: j}, []judge.Failure{
		{CaseID: c.ID, Kind: "missed-concern", ConcernID: "c-miss", Detail: "missed", ReviewerID: "engineering-review"},
		{CaseID: c.ID, Kind: "false-positive", FindingID: "er-2", Detail: "fp", ReviewerID: "engineering-review"},
	})
	exp := &experiment.Report{
		Status: "needs-human-review", CandidateScoresMode: "identical_to_base",
		BaseFailures: 2, CandidateFailures: 2, Hypothesis: "Tighten claim gates.",
	}
	// Catalog-author: local package named engineering-review may receive drafts.
	// Customer mode would leave LocalIDs empty of this official id and suppress drafts.
	res, err := Write(Input{
		RunID: "slice-test", DataRoot: dir, RunDir: runDir, ExperimentDir: expDir,
		Fixture: true, Scorecard: sc, Cases: []*cases.Case{c},
		Judgments:   map[string]*judge.ReviewJudgment{c.ID: j},
		NormReviews: map[string]*normalize.Review{c.ID: rev},
		Experiment:  exp, ProposalPatch: filepath.Join(expDir, "exp.patch"),
		LocalIDs: map[string]bool{"engineering-review": true},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Story in experiment dir (what user opens)
	raw, err := os.ReadFile(filepath.Join(expDir, "STORY.md"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)

	// Must be story language (owner-aware: miss narrative names the owning adversary)
	for _, want := range []string{
		"Bottom line",
		"What the human reviewer said",
		"What `engineering-review` said",
		"What we concluded",
		"We missed something a human caught",
		"Export errors ignored",
		"Caught by",
		"https://github.com/open-telemetry/opentelemetry-go/pull/9001",
		"What should I do next",
		"Suggested GitHub issue",
		"Export errors ignored",
		"Nothing was filed",
		"best-fit adversary",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("story missing %q\n\n%s", want, s[:min(1200, len(s))])
		}
	}
	if _, err := os.Stat(filepath.Join(expDir, "SUGGESTED_ISSUES.md")); err != nil {
		t.Fatal("expected SUGGESTED_ISSUES.md")
	}

	// Must NOT lead with scorecard jargon tables
	for _, bad := range []string{
		"Important concern recall",
		"False-positive rate",
		"Unsupported-claim rate",
		"execution_class",
		"candidate_scores_mode",
	} {
		if strings.Contains(s, bad) {
			t.Fatalf("story still has jargon %q", bad)
		}
	}

	// CLI block plain — points at results inbox, not jargon metrics
	if !strings.Contains(res.CLIBlock, "BOTTOM LINE") || !strings.Contains(res.CLIBlock, "train results ls") {
		t.Fatalf("CLI block: %s", res.CLIBlock)
	}
	if strings.Contains(res.CLIBlock, "Precision:") || strings.Contains(res.CLIBlock, "False-positive") {
		t.Fatalf("CLI still has metrics: %s", res.CLIBlock)
	}
}

func TestSuggestIssuesNeverDraftsOfficialOwners(t *testing.T) {
	dir := t.TempDir()
	runDir := filepath.Join(dir, "runs", "off")
	expDir := filepath.Join(dir, "experiments", "off")
	c := &cases.Case{
		ID:          "case-1",
		Repository:  cases.Repository{Owner: "o", Name: "r", URL: "https://github.com/o/r/pull/1"},
		PullRequest: cases.PullRequest{Number: 1, Title: "t"},
		Labels: cases.Labels{ExpectedConcerns: []cases.ExpectedConcern{
			{ID: "c1", Summary: "secret in HCL", Approved: true, OwnerAdversary: "go-security", Importance: "high"},
		}},
	}
	sc := score.Aggregate("go-security", map[string]*judge.ReviewJudgment{
		c.ID: {ReviewerID: "go-security", ExpectedMissed: []string{"c1"}},
	}, []judge.Failure{
		{CaseID: c.ID, Kind: "missed-concern", ConcernID: "c1", ReviewerID: "go-security"},
	})
	_, err := Write(Input{
		RunID: "x", DataRoot: dir, RunDir: runDir, ExperimentDir: expDir,
		Scorecard: sc, Cases: []*cases.Case{c},
		// Customer workspace: only my-policy is local; go-security is official.
		LocalIDs:    map[string]bool{"my-policy": true},
		OfficialIDs: map[string]bool{"go-security": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(expDir, "SUGGESTED_ISSUES.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, "go-security:") || strings.Contains(text, "Adversary: `go-security`") {
		t.Fatalf("must not draft for official go-security:\n%s", text)
	}
	if strings.Contains(text, "engineering-review:") {
		t.Fatalf("must not draft for official engineering-review:\n%s", text)
	}
}

func TestSuggestIssuesDraftsLocalOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	runDir := filepath.Join(dir, "runs", "loc")
	expDir := filepath.Join(dir, "experiments", "loc")
	c := &cases.Case{
		ID:          "case-1",
		Repository:  cases.Repository{Owner: "o", Name: "r", URL: "https://github.com/o/r/pull/1"},
		PullRequest: cases.PullRequest{Number: 1, Title: "t"},
		Labels: cases.Labels{ExpectedConcerns: []cases.ExpectedConcern{
			{ID: "c1", Summary: "company policy violated", Approved: true, OwnerAdversary: "my-policy", Importance: "high"},
		}},
	}
	sc := score.Aggregate("my-policy", map[string]*judge.ReviewJudgment{
		c.ID: {ReviewerID: "my-policy", ExpectedMissed: []string{"c1"}},
	}, []judge.Failure{
		{CaseID: c.ID, Kind: "missed-concern", ConcernID: "c1", ReviewerID: "my-policy"},
	})
	_, err := Write(Input{
		RunID: "x", DataRoot: dir, RunDir: runDir, ExperimentDir: expDir,
		Scorecard: sc, Cases: []*cases.Case{c},
		LocalIDs:    map[string]bool{"my-policy": true},
		PriorMisses: []MissEvidence{{Package: "my-policy", Summary: "company policy is violated by this path", PRURL: "https://github.com/other/repo/pull/2"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(expDir, "SUGGESTED_ISSUES.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, "What we want to improve") || !strings.Contains(text, "Teach `my-policy`") {
		t.Fatalf("expected local draft:\n%s", text)
	}
	// Official catch suppresses
	_, err = Write(Input{
		RunID: "y", DataRoot: dir, RunDir: filepath.Join(dir, "runs", "sup"), ExperimentDir: filepath.Join(dir, "experiments", "sup"),
		Scorecard: sc, Cases: []*cases.Case{c},
		LocalIDs:               map[string]bool{"my-policy": true},
		OfficialCatchByConcern: map[string]string{"c1": "go-testing"},
		PriorMisses:            []MissEvidence{{Package: "my-policy", Summary: "company policy is violated by this path", PRURL: "https://github.com/other/repo/pull/2"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw2, _ := os.ReadFile(filepath.Join(dir, "experiments", "sup", "SUGGESTED_ISSUES.md"))
	if strings.Contains(string(raw2), "Teach `my-policy`") {
		t.Fatalf("official catch should suppress local draft:\n%s", raw2)
	}
}

func TestSuggestIssuesRequiresTwoIndependentPullRequests(t *testing.T) {
	c := &cases.Case{
		ID:         "case-one",
		Repository: cases.Repository{URL: "https://github.com/acme/one/pull/1"},
		Labels: cases.Labels{ExpectedConcerns: []cases.ExpectedConcern{{
			ID: "validation", Summary: "The test reaches the branch but does not assert the result.",
			OwnerAdversary: "engineering-review", Approved: true,
		}}},
	}
	failure := judge.Failure{CaseID: c.ID, Kind: "missed-concern", ConcernID: "validation", ReviewerID: "engineering-review"}
	sc := score.Aggregate("engineering-review", map[string]*judge.ReviewJudgment{
		c.ID: {ReviewerID: "engineering-review", ExpectedMissed: []string{"validation"}},
	}, []judge.Failure{failure})
	base := Input{Scorecard: sc, Cases: []*cases.Case{c}, LocalIDs: map[string]bool{"engineering-review": true}}
	if issues := suggestIssues(base); len(issues) != 0 {
		t.Fatalf("one PR must remain local evidence, got %#v", issues)
	}
	base.PriorMisses = []MissEvidence{{
		Package: "engineering-review", Summary: "Coverage reaches a branch without asserting its result.",
		PRURL: "https://github.com/acme/one/pull/1#discussion_r9",
	}}
	if issues := suggestIssues(base); len(issues) != 0 {
		t.Fatalf("two comments from one PR are not independent evidence: %#v", issues)
	}
	base.PriorMisses[0].PRURL = "https://github.com/other/two/pull/2"
	if issues := suggestIssues(base); len(issues) != 1 {
		t.Fatalf("two independent PRs should corroborate one draft: %#v", issues)
	}
}

func TestSuggestIssuesRejectsUnavailableReviewInputs(t *testing.T) {
	c := &cases.Case{
		ID:         "case-metadata",
		Repository: cases.Repository{URL: "https://github.com/acme/one/pull/1"},
		Labels: cases.Labels{ExpectedConcerns: []cases.ExpectedConcern{{
			ID: "metadata", Summary: "The PR description promises a migration that the implementation does not provide.",
			OwnerAdversary: "engineering-review", Approved: true,
		}}},
	}
	failure := judge.Failure{CaseID: c.ID, Kind: "missed-concern", ConcernID: "metadata", ReviewerID: "engineering-review"}
	sc := score.Aggregate("engineering-review", map[string]*judge.ReviewJudgment{
		c.ID: {ReviewerID: "engineering-review", ExpectedMissed: []string{"metadata"}},
	}, []judge.Failure{failure})
	issues := suggestIssues(Input{
		Scorecard: sc, Cases: []*cases.Case{c}, LocalIDs: map[string]bool{"engineering-review": true},
		PriorMisses: []MissEvidence{{
			Package: "engineering-review", Summary: "The pull request description claims behavior absent from the code.",
			PRURL: "https://github.com/other/two/pull/2",
		}},
	})
	if len(issues) != 0 {
		t.Fatalf("metadata-dependent capability cannot become a draft: %#v", issues)
	}
}

func TestSuggestIssuesDoesNotClusterUnrelatedGeneralMisses(t *testing.T) {
	c := &cases.Case{
		ID:         "case-general",
		Repository: cases.Repository{URL: "https://github.com/acme/one/pull/1"},
		Labels: cases.Labels{ExpectedConcerns: []cases.ExpectedConcern{{
			ID: "naming", Summary: "Prefer a clear local variable for the parsed tenant identifier.",
			OwnerAdversary: "my-review", Approved: true,
		}}},
	}
	failure := judge.Failure{CaseID: c.ID, Kind: "missed-concern", ConcernID: "naming", ReviewerID: "my-review"}
	sc := score.Aggregate("my-review", map[string]*judge.ReviewJudgment{
		c.ID: {ReviewerID: "my-review", ExpectedMissed: []string{"naming"}},
	}, []judge.Failure{failure})
	issues := suggestIssues(Input{
		Scorecard: sc, Cases: []*cases.Case{c}, LocalIDs: map[string]bool{"my-review": true},
		PriorMisses: []MissEvidence{{
			Package: "my-review", Summary: "Guard cache eviction against missing entries.",
			PRURL: "https://github.com/other/two/pull/2",
		}},
	})
	if len(issues) != 0 {
		t.Fatalf("same package and class are insufficient without shared intent: %#v", issues)
	}
}

func TestSameConcernIntentRejectsOneSharedWordInBroadClass(t *testing.T) {
	if sameConcernIntent(
		"meaningful-validation",
		"The migration test never verifies the emitted audit event.",
		[]string{"The parser test reaches the branch without checking its return value."},
	) {
		t.Fatal("one generic shared token must not corroborate distinct validation intents")
	}
	if !sameConcernIntent(
		"meaningful-validation",
		"Coverage reaches the branch but never asserts the returned value.",
		[]string{"The test reaches the branch without checking its return value."},
	) {
		t.Fatal("multiple intent-specific tokens should corroborate the same validation gap")
	}
}

func TestEngineeringReviewConcernClassesClusterByPrinciple(t *testing.T) {
	cases := []struct {
		summary string
		wantKey string
	}{
		{"The same validation regex is duplicated in two places.", "source-of-truth"},
		{"This serializes every manifest although the result is not used.", "proportional-work"},
		{"The public contract changes but the downstream adapter still rejects the value.", "contract-integrity"},
		{"This bypasses the private boundary instead of using the trait.", "ownership-boundaries"},
		{"The asynchronous refresh can consume stale state in a race condition.", "state-lifecycle"},
		{"The test reaches the branch but does not assert the externally visible result.", "meaningful-validation"},
		{"This major version update has no compatibility analysis.", "compatibility-operations"},
	}
	for _, tc := range cases {
		key, _ := classifyConcernClass("engineering-review", tc.summary)
		if key != tc.wantKey {
			t.Errorf("summary %q: key=%q want %q", tc.summary, key, tc.wantKey)
		}
	}
}
