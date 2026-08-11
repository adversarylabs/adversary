package report

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/adversarylabs/adversary/internal/modelreview"
	"github.com/adversarylabs/adversary/internal/train/cases"
	"github.com/adversarylabs/adversary/internal/train/judge"
	"github.com/adversarylabs/adversary/internal/train/score"
)

type fixtureBriefProvider struct {
	request modelreview.Request
}

type fixtureAssessmentProvider struct {
	request    modelreview.Request
	detectable bool
	abstract   bool
}

func (p *fixtureAssessmentProvider) Name() string  { return "fixture" }
func (p *fixtureAssessmentProvider) Model() string { return "fixture" }
func (p *fixtureAssessmentProvider) Review(_ context.Context, request modelreview.Request) (modelreview.Result, error) {
	p.request = request
	return modelreview.Result{Output: json.RawMessage(fmt.Sprintf(`{
  "should_abstract": %t,
  "reason": "The finding identifies a transferable changed-code mechanism rather than a repository preference.",
  "causal_mechanism": "A newly added operation duplicates a guarantee already provided on every downstream route and obscures ownership.",
  "transfer_test": "The same issue appears in rendering and storage pipelines, while a bypass route is a counterexample.",
  "detectable_in_diff": %t
}`, p.abstract, p.detectable))}, nil
}

func TestIssueBriefWriterDefaultsToHigherQualityOpenAIModel(t *testing.T) {
	writer, err := NewModelIssueBriefWriterFromEnvironment(func(key string) (string, bool) {
		if key == modelreview.OpenAIKeyEnv {
			return "test-key", true
		}
		return "", false
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	modelWriter, ok := writer.(*modelIssueBriefWriter)
	if !ok || modelWriter.provider.Model() != "gpt-5-mini" {
		t.Fatalf("default issue brief model=%T/%q", writer, modelWriter.provider.Model())
	}
}

func (p *fixtureBriefProvider) Name() string  { return "fixture" }
func (p *fixtureBriefProvider) Model() string { return "fixture" }
func (p *fixtureBriefProvider) Review(_ context.Context, request modelreview.Request) (modelreview.Result, error) {
	if p.request.Prompt == "" {
		p.request = request
	}
	return modelreview.Result{Output: json.RawMessage(`{
  "title": "Flag unrelated behavior that makes a change unsafe to roll back",
  "intent": "Review the changed code as one engineering unit and call out behavior that has no necessary relationship to the main implementation story.",
  "why": "Bundling independent behavior hides scope, weakens validation, and forces maintainers to roll back otherwise unrelated changes together.",
  "examples": [
    "A retry-policy fix also disables avatar caching even though the two behaviors have no shared contract.",
    "A parser correction quietly changes an unrelated session timeout in another subsystem."
  ],
  "counterexamples": [
    "A schema change and the required consumer updates belong together even when they span several directories."
  ],
  "acceptance": [
    "A positive fixture reports an independently batched behavior with evidence from both objectives.",
    "A cohesive multi-file migration remains quiet."
  ]
}`)}, nil
}

func TestModelIssueBriefWriterSynthesizesIntent(t *testing.T) {
	provider := &fixtureBriefProvider{}
	writer := &modelIssueBriefWriter{provider: provider}
	brief, err := writer.WriteIssueBrief(context.Background(), IssueBriefInput{
		Package:      "engineering-review",
		PackageScope: "Staff-level review of correctness, maintainability, and operational risk.",
		ConcernClass: "change-cohesion",
		Evidence: []IssueBriefEvidence{{
			Concern: "why are these changes here? This seems unrelated",
			PRTitle: "fix operator precedence",
			File:    "sessionmanager.go",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(brief.Title, "unsafe to roll back") {
		t.Fatalf("unexpected brief: %#v", brief)
	}
	if strings.Contains(brief.Intent, "why are these changes here") {
		t.Fatalf("writer only paraphrased the comment: %#v", brief)
	}
	if !strings.Contains(provider.request.Prompt, "Do not merely restate") {
		t.Fatalf("prompt does not protect intent synthesis:\n%s", provider.request.Prompt)
	}
	if !strings.Contains(provider.request.Prompt, "untrusted evidence") {
		t.Fatalf("prompt does not protect against evidence injection:\n%s", provider.request.Prompt)
	}
	if !strings.Contains(provider.request.Prompt, "package_scope is only an ownership boundary") ||
		!strings.Contains(provider.request.Prompt, "same causal mechanism") ||
		!strings.Contains(provider.request.Prompt, "portable technical identifiers") ||
		!strings.Contains(provider.request.Prompt, "at most 45 words") {
		t.Fatalf("prompt does not require evidence-grounded generalization:\n%s", provider.request.Prompt)
	}
	if !strings.Contains(string(provider.request.Input), "Staff-level review") {
		t.Fatalf("package scope missing from model input: %s", provider.request.Input)
	}
	if provider.request.Budget.MaximumOutputTokens != issueBriefMaximumOutputTokens || issueBriefMaximumOutputTokens < 4_000 {
		t.Fatalf("issue brief budget=%d is too small for reasoning models", provider.request.Budget.MaximumOutputTokens)
	}
	rendered := renderIssueBrief(brief)
	for _, want := range []string{"What we want to improve", "Why this matters", "Examples", "Keep it focused", "Done when"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("rendered brief missing %q:\n%s", want, rendered)
		}
	}
}

func TestModelIssueAbstractionJudgeAdmitsReusableSingleton(t *testing.T) {
	provider := &fixtureAssessmentProvider{abstract: true, detectable: true}
	writer := &modelIssueBriefWriter{provider: provider}
	assessment, err := writer.AssessIssueAbstraction(context.Background(), IssueBriefInput{
		Package:      "engineering-review",
		PackageScope: "Staff-level review of correctness and maintainability.",
		ConcernClass: "redundant-operation",
		Evidence:     []IssueBriefEvidence{{Concern: "Every downstream route already performs this transformation."}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !assessment.ShouldAbstract || !assessment.DetectableInDiff {
		t.Fatalf("reusable singleton rejected: %#v", assessment)
	}
	if !strings.Contains(provider.request.Prompt, "One source PR is sufficient") ||
		!strings.Contains(provider.request.Prompt, "two concrete hypothetical examples") ||
		!strings.Contains(provider.request.Prompt, "changed head-side code") {
		t.Fatalf("abstraction prompt is missing admission safeguards:\n%s", provider.request.Prompt)
	}
}

func TestModelIssueAbstractionJudgeRejectsUnavailableInput(t *testing.T) {
	provider := &fixtureAssessmentProvider{abstract: true, detectable: false}
	writer := &modelIssueBriefWriter{provider: provider}
	assessment, err := writer.AssessIssueAbstraction(context.Background(), IssueBriefInput{
		Package:  "engineering-review",
		Evidence: []IssueBriefEvidence{{Concern: "The PR description promised behavior absent from the implementation."}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if assessment.ShouldAbstract {
		t.Fatalf("metadata-dependent singleton admitted: %#v", assessment)
	}
}

type fixtureRefinementProvider struct {
	requests []modelreview.Request
}

func (p *fixtureRefinementProvider) Name() string  { return "fixture" }
func (p *fixtureRefinementProvider) Model() string { return "fixture" }
func (p *fixtureRefinementProvider) Review(_ context.Context, request modelreview.Request) (modelreview.Result, error) {
	p.requests = append(p.requests, request)
	if len(p.requests) == 1 {
		return modelreview.Result{Output: json.RawMessage(`{
  "title": "Avoid redundant masking before Trace.Error",
  "intent": "Detect calls to MaskUserVisibleText when Trace.Error and ExecutionContext already guarantee that the same value is masked downstream.",
  "why": "Duplicating the operation obscures which layer owns the guarantee and leaves unnecessary code in the changed path.",
  "examples": ["Trace.Error receives an already masked value.", "ExecutionContext masks the same annotation twice."],
  "counterexamples": ["A direct client payload bypasses the normal masking path."],
  "acceptance": ["Remove MaskUserVisibleText from this path.", "Keep the direct payload masking path unchanged."]
}`)}, nil
	}
	return modelreview.Result{Output: json.RawMessage(`{
  "title": "Flag operations already guaranteed by every downstream path",
  "intent": "Detect a newly added transformation when every route from that call site already performs the same transformation, and explain the existing guarantee that makes the new call redundant.",
  "why": "Keeping ownership of a cross-cutting guarantee in one layer makes the data flow easier to reason about and avoids misleading future maintainers about which call is required.",
  "examples": ["A web handler escapes a value before passing it to a renderer that escapes every interpolation.", "A storage adapter normalizes a key before calling an API that normalizes all accepted keys."],
  "counterexamples": ["A value is sent through a direct transport that bypasses the normal transformation layer."],
  "acceptance": ["A positive fixture emits a focused finding when all downstream routes already perform the operation.", "A negative fixture stays quiet when one route bypasses the downstream guarantee."]
}`)}, nil
}

func TestModelIssueBriefWriterRefinesSourceSpecificDraft(t *testing.T) {
	provider := &fixtureRefinementProvider{}
	writer := &modelIssueBriefWriter{provider: provider}
	brief, err := writer.WriteIssueBrief(context.Background(), IssueBriefInput{
		Package: "nits", PackageScope: "Non-blocking maintainer cleanup.", ConcernClass: "redundant-operation",
		Evidence: []IssueBriefEvidence{{Concern: "`Trace.Error` already masks this value through `ExecutionContext`; `MaskUserVisibleText` is only for bypass paths."}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(provider.requests) != 2 {
		t.Fatalf("model calls=%d want 2", len(provider.requests))
	}
	if briefUsesSourceIdentifiers(brief, sourceIdentifiers([]IssueBriefEvidence{{Concern: "`Trace.Error` `ExecutionContext` `MaskUserVisibleText`"}})) {
		t.Fatalf("refined brief retained source identifiers: %#v", brief)
	}
	if !strings.Contains(brief.Acceptance[0], "fixture emits") || !strings.Contains(provider.requests[1].Prompt, "observable adversary behavior") {
		t.Fatalf("refinement did not target adversary behavior: %#v\n%s", brief, provider.requests[1].Prompt)
	}
}

type fixturePortableIdentifierProvider struct{}

func (*fixturePortableIdentifierProvider) Name() string  { return "fixture" }
func (*fixturePortableIdentifierProvider) Model() string { return "fixture" }
func (*fixturePortableIdentifierProvider) Review(_ context.Context, _ modelreview.Request) (modelreview.Result, error) {
	return modelreview.Result{Output: json.RawMessage(`{
  "title": "Detect ModePerm in directory creation",
  "intent": "Detect os.ModePerm or fs.ModePerm passed to directory-creation APIs because the symbolic constant requests permission bits 0777 before umask.",
  "why": "The name reads like a safe default even though most private or executable directories should request an explicit narrower mode.",
  "examples": ["A service creates its private state directory with os.ModePerm.", "A command creates a shared executable cache with fs.ModePerm."],
  "counterexamples": ["Code masks a reported file mode with os.ModePerm only to inspect its permission bits."],
  "acceptance": ["A positive fixture using os.ModePerm for directory creation emits a focused finding.", "A mask-only fixture using os.ModePerm remains quiet."]
}`)}, nil
}

func TestModelIssueBriefWriterKeepsEssentialPortableIdentifier(t *testing.T) {
	writer := &modelIssueBriefWriter{provider: &fixturePortableIdentifierProvider{}}
	brief, err := writer.WriteIssueBrief(context.Background(), IssueBriefInput{
		Package:  "go",
		Evidence: []IssueBriefEvidence{{Concern: "`os.ModePerm` is 0777 and should not be passed to `os.MkdirAll`."}},
		Abstraction: &IssueAbstractionAssessment{
			ShouldAbstract: true, DetectableInDiff: true,
			CausalMechanism: "ModePerm requests all permission bits when used as a directory creation mode.",
			TransferTest:    "Different directory-creation call sites share the same standard-library API mistake.",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(brief)
	if !strings.Contains(string(raw), "os.ModePerm") {
		t.Fatalf("portable identifier defining the mechanism was removed: %#v", brief)
	}
}

func TestSuggestIssuesUsesFullSourceCommentAsBriefEvidence(t *testing.T) {
	const fullComment = "This value is already masked on every path it takes. The trace manager masks logs and the issue recorder masks annotations. The new helper is only for protocol payloads that bypass both paths, so it is not applicable here."
	c := &cases.Case{
		ID:          "case-masking",
		Repository:  cases.Repository{URL: "https://github.com/acme/one/pull/1"},
		PullRequest: cases.PullRequest{Title: "Report a debugger infrastructure failure"},
		Comments:    []cases.Comment{{ID: 42, Body: fullComment, Path: "debugger.cs"}},
		Labels: cases.Labels{ExpectedConcerns: []cases.ExpectedConcern{{
			ID: "c-42-0", Summary: "This value is already masked on every path it takes…", File: "debugger.cs",
			Importance: "medium", OwnerAdversary: "nits", Approved: true,
		}}},
	}
	failure := judge.Failure{CaseID: c.ID, Kind: "missed-concern", ConcernID: "c-42-0", ReviewerID: "nits"}
	sc := score.Aggregate("nits", map[string]*judge.ReviewJudgment{
		c.ID: {ReviewerID: "nits", ExpectedMissed: []string{"c-42-0"}},
	}, []judge.Failure{failure})
	writer := &captureBriefWriter{}
	issues := suggestIssues(Input{
		Context: context.Background(), Scorecard: sc, Cases: []*cases.Case{c},
		LocalIDs: map[string]bool{"nits": true}, IssueBriefWriter: writer,
		PriorMisses: []MissEvidence{{Package: "nits", Summary: "This validation is already guaranteed on every downstream path.", PRURL: "https://github.com/acme/two/pull/2"}},
	})
	if len(issues) != 1 {
		t.Fatalf("issues=%d %#v", len(issues), issues)
	}
	if writer.input.ConcernClass != "redundant-operation" {
		t.Fatalf("concern class=%q", writer.input.ConcernClass)
	}
	if got := writer.input.Evidence[0].Concern; got != fullComment {
		t.Fatalf("brief evidence was truncated:\n%s", got)
	}
}

type captureBriefWriter struct {
	input IssueBriefInput
}

func (w *captureBriefWriter) WriteIssueBrief(_ context.Context, in IssueBriefInput) (IssueBrief, error) {
	w.input = in
	return IssueBrief{
		Title:  "Detect independent behavior hidden inside an otherwise focused change",
		Intent: "Teach the reviewer to recognize when a change contains a second behavior objective that is not required by the primary implementation story.",
		Why:    "Independent behavior deserves separate validation and rollback so maintainers can reason about each change without hidden coupling.",
		Examples: []string{
			"A bug fix also changes an unrelated cache policy.",
			"A refactor quietly alters a timeout in another subsystem.",
		},
		Counterexamples: []string{"A contract migration updates its model, adapter, and tests together."},
		Acceptance: []string{
			"A positive fixture reports concrete independent behavior.",
			"A cohesive cross-layer change remains quiet.",
		},
	}, nil
}

type judgingBriefWriter struct {
	captureBriefWriter
	assessment    IssueAbstractionAssessment
	assessmentErr error
	writes        int
}

func (w *judgingBriefWriter) AssessIssueAbstraction(_ context.Context, _ IssueBriefInput) (IssueAbstractionAssessment, error) {
	return w.assessment, w.assessmentErr
}

func TestSuggestIssuesKeepsCorroboratedFallbackWhenJudgmentFails(t *testing.T) {
	c := &cases.Case{
		ID:         "case-corroborated",
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
	writer := &judgingBriefWriter{assessmentErr: errors.New("temporary model failure")}
	issues := suggestIssues(Input{
		Scorecard: sc, Cases: []*cases.Case{c}, LocalIDs: map[string]bool{"engineering-review": true}, IssueBriefWriter: writer,
		PriorMisses: []MissEvidence{{Package: "engineering-review", Summary: "Coverage reaches a branch without asserting its result.", PRURL: "https://github.com/acme/two/pull/2"}},
	})
	if len(issues) != 1 || writer.writes != 1 {
		t.Fatalf("corroborated candidate was lost after judgment error: issues=%#v writes=%d", issues, writer.writes)
	}
}

func (w *judgingBriefWriter) WriteIssueBrief(ctx context.Context, in IssueBriefInput) (IssueBrief, error) {
	w.writes++
	return w.captureBriefWriter.WriteIssueBrief(ctx, in)
}

func TestSuggestIssuesLetsAbstractionJudgeDecideSingletons(t *testing.T) {
	c := &cases.Case{
		ID:         "case-singleton",
		Repository: cases.Repository{URL: "https://github.com/acme/one/pull/1"},
		Labels: cases.Labels{ExpectedConcerns: []cases.ExpectedConcern{{
			ID: "redundant", Summary: "Every downstream route already performs this transformation.",
			OwnerAdversary: "engineering-review", Approved: true,
		}}},
	}
	failure := judge.Failure{CaseID: c.ID, Kind: "missed-concern", ConcernID: "redundant", ReviewerID: "engineering-review"}
	sc := score.Aggregate("engineering-review", map[string]*judge.ReviewJudgment{
		c.ID: {ReviewerID: "engineering-review", ExpectedMissed: []string{"redundant"}},
	}, []judge.Failure{failure})

	accepted := &judgingBriefWriter{assessment: IssueAbstractionAssessment{
		ShouldAbstract: true, DetectableInDiff: true, Reason: "reusable", CausalMechanism: "duplicate guarantee", TransferTest: "two domains",
	}}
	issues := suggestIssues(Input{Scorecard: sc, Cases: []*cases.Case{c}, LocalIDs: map[string]bool{"engineering-review": true}, IssueBriefWriter: accepted})
	if len(issues) != 1 || accepted.writes != 1 || len(accepted.input.Evidence) != 1 ||
		accepted.input.Abstraction == nil || accepted.input.Abstraction.CausalMechanism != "duplicate guarantee" {
		t.Fatalf("accepted singleton did not produce one issue: issues=%#v writer=%#v", issues, accepted)
	}

	rejected := &judgingBriefWriter{assessment: IssueAbstractionAssessment{
		ShouldAbstract: false, DetectableInDiff: true, Reason: "one-off preference", CausalMechanism: "none", TransferTest: "does not transfer",
	}}
	if issues := suggestIssues(Input{Scorecard: sc, Cases: []*cases.Case{c}, LocalIDs: map[string]bool{"engineering-review": true}, IssueBriefWriter: rejected}); len(issues) != 0 {
		t.Fatalf("rejected singleton produced an issue: %#v", issues)
	}
	if rejected.writes != 0 {
		t.Fatalf("rejected singleton still invoked brief writer %d time(s)", rejected.writes)
	}
}

type unavailableInputBriefWriter struct{}

func (unavailableInputBriefWriter) WriteIssueBrief(_ context.Context, _ IssueBriefInput) (IssueBrief, error) {
	return IssueBrief{
		Title:  "Compare implementation with promised behavior",
		Intent: "Detect when implementation details diverge from the behavior promised to maintainers.",
		Why:    "Unnoticed divergence can make a change incomplete even when the changed code is internally consistent.",
		Examples: []string{
			"A migration updates storage but omits one required consumer.",
			"A new mode updates parsing but leaves execution unchanged.",
		},
		Counterexamples: []string{"A cohesive implementation updates every affected layer."},
		Acceptance: []string{
			"A positive fixture compares the PR description with the implementation.",
			"A complete implementation remains quiet.",
		},
	}, nil
}

func TestSuggestIssuesRejectsGeneratedBriefThatNeedsUnavailableInputs(t *testing.T) {
	c := &cases.Case{
		ID:         "case-contract",
		Repository: cases.Repository{URL: "https://github.com/acme/one/pull/1"},
		Labels: cases.Labels{ExpectedConcerns: []cases.ExpectedConcern{{
			ID: "contract", Summary: "The contract changes but the downstream adapter still rejects the value.",
			OwnerAdversary: "engineering-review", Approved: true,
		}}},
	}
	failure := judge.Failure{CaseID: c.ID, Kind: "missed-concern", ConcernID: "contract", ReviewerID: "engineering-review"}
	sc := score.Aggregate("engineering-review", map[string]*judge.ReviewJudgment{
		c.ID: {ReviewerID: "engineering-review", ExpectedMissed: []string{"contract"}},
	}, []judge.Failure{failure})
	issues := suggestIssues(Input{
		Scorecard: sc, Cases: []*cases.Case{c}, LocalIDs: map[string]bool{"engineering-review": true},
		IssueBriefWriter: unavailableInputBriefWriter{},
		PriorMisses: []MissEvidence{{
			Package: "engineering-review", Summary: "A downstream adapter still rejects the newly supported contract value.",
			PRURL: "https://github.com/other/two/pull/2",
		}},
	})
	if len(issues) != 0 {
		t.Fatalf("generated acceptance criteria require unavailable PR metadata: %#v", issues)
	}
}

func TestSuggestIssuesUsesModelBriefAndPackageScope(t *testing.T) {
	c := &cases.Case{
		ID:          "case-1",
		Repository:  cases.Repository{URL: "https://github.com/acme/one/pull/1"},
		PullRequest: cases.PullRequest{Title: "fix operator precedence"},
		Labels: cases.Labels{ExpectedConcerns: []cases.ExpectedConcern{{
			ID: "concern-1", Summary: "why are these changes here?", File: "session.go",
			Importance: "medium", ScopeReason: "change cohesion is staff-level judgment",
			OwnerAdversary: "engineering-review", Approved: true,
		}}},
	}
	failure := judge.Failure{CaseID: c.ID, Kind: "missed-concern", ConcernID: "concern-1", ReviewerID: "engineering-review"}
	sc := score.Aggregate("engineering-review", map[string]*judge.ReviewJudgment{
		c.ID: {ReviewerID: "engineering-review", ExpectedMissed: []string{"concern-1"}},
	}, []judge.Failure{failure})
	writer := &captureBriefWriter{}
	issues := suggestIssues(Input{
		Context:          context.Background(),
		Scorecard:        sc,
		Cases:            []*cases.Case{c},
		LocalIDs:         map[string]bool{"engineering-review": true},
		PackageScopes:    map[string]string{"engineering-review": "Staff-level residual engineering judgment."},
		IssueBriefWriter: writer,
		PriorMisses:      []MissEvidence{{Package: "engineering-review", Summary: "Why is this unrelated behavior bundled into the focused fix?", PRURL: "https://github.com/acme/two/pull/2"}},
	})
	if len(issues) != 1 {
		t.Fatalf("issues=%d %#v", len(issues), issues)
	}
	if issues[0].Title != "Detect independent behavior hidden inside an otherwise focused change" {
		t.Fatalf("model title not used: %#v", issues[0])
	}
	if !strings.HasPrefix(issues[0].Key, "engineering-review|change-cohesion|evidence:") {
		t.Fatalf("stable concern key missing: %#v", issues[0])
	}
	if strings.Contains(issues[0].Body, "Task for coding agent") || strings.Contains(issues[0].Body, "Example concern classes") {
		t.Fatalf("legacy boilerplate leaked into generated brief:\n%s", issues[0].Body)
	}
	if writer.input.PackageScope != "Staff-level residual engineering judgment." {
		t.Fatalf("scope not passed to writer: %#v", writer.input)
	}
	if len(writer.input.Evidence) != 2 || writer.input.Evidence[0].PRTitle != "fix operator precedence" {
		t.Fatalf("source context not passed to writer: %#v", writer.input)
	}
}

func TestIssueSemanticKeyDistinguishesCapabilitiesWithinOneConcernClass(t *testing.T) {
	paginationEvidence := []IssueBriefEvidence{{Concern: "Advance the pagination offset by records consumed so short pages do not skip records."}}
	pagination := issueSemanticKey("engineering-review", "general", paginationEvidence)
	constraints := issueSemanticKey("engineering-review", "general", []IssueBriefEvidence{{
		Concern: "Keep each listener constraint separate so one listener does not reject routes for another.",
	}})
	if pagination == constraints {
		t.Fatalf("unrelated general capabilities share key %q", pagination)
	}
	if pagination != issueSemanticKey("Engineering-Review", "GENERAL", []IssueBriefEvidence{{
		Concern: "  Advance   the pagination offset by records consumed so short pages do not skip records.  ",
	}}) {
		t.Fatalf("semantic key should ignore case and whitespace: %q", pagination)
	}
}

func TestIssueSemanticKeyDoesNotDependOnModelBriefWording(t *testing.T) {
	evidence := []IssueBriefEvidence{{Concern: "A short non-final page advances past records that were not consumed."}}
	first := issueSemanticKey("engineering-review", "general", evidence)
	second := issueSemanticKey("engineering-review", "general", evidence)
	if first != second {
		t.Fatalf("same admitted evidence produced unstable keys: %q != %q", first, second)
	}
}

type barrierBriefWriter struct {
	mu      sync.Mutex
	started int
	release chan struct{}
}

func (w *barrierBriefWriter) WriteIssueBrief(_ context.Context, _ IssueBriefInput) (IssueBrief, error) {
	w.mu.Lock()
	w.started++
	if w.started == 2 {
		close(w.release)
	}
	w.mu.Unlock()
	<-w.release
	return IssueBrief{
		Title:  "Improve this review capability",
		Intent: "Recognize the generalized concern from concrete changed-code evidence without matching one comment's surface wording.",
		Why:    "The signal should transfer across repositories while preserving the package's existing ownership and confidence boundaries.",
		Examples: []string{
			"A changed path demonstrates the material concern with a concrete consequence.",
			"A different implementation exposes the same reasoning class with source evidence.",
		},
		Counterexamples: []string{"A superficially similar change lacks the consequence that makes the concern material."},
		Acceptance: []string{
			"A positive fixture demonstrates the generalized concern.",
			"A clean counterexample remains quiet.",
		},
	}, nil
}

func TestSuggestIssuesGeneratesIndependentBriefsConcurrently(t *testing.T) {
	c := &cases.Case{
		ID:         "case-concurrent",
		Repository: cases.Repository{URL: "https://github.com/acme/one/pull/1"},
		Labels: cases.Labels{ExpectedConcerns: []cases.ExpectedConcern{
			{ID: "validation", Summary: "The test reaches the branch but does not assert the result.", OwnerAdversary: "engineering-review", Approved: true},
			{ID: "contract", Summary: "The public contract changes but the downstream adapter still rejects the value.", OwnerAdversary: "engineering-review", Approved: true},
		}},
	}
	failures := []judge.Failure{
		{CaseID: c.ID, Kind: "missed-concern", ConcernID: "validation", ReviewerID: "engineering-review"},
		{CaseID: c.ID, Kind: "missed-concern", ConcernID: "contract", ReviewerID: "engineering-review"},
	}
	sc := score.Aggregate("engineering-review", map[string]*judge.ReviewJudgment{
		c.ID: {ReviewerID: "engineering-review", ExpectedMissed: []string{"validation", "contract"}},
	}, failures)
	writer := &barrierBriefWriter{release: make(chan struct{})}
	done := make(chan []SuggestedIssue, 1)
	go func() {
		done <- suggestIssues(Input{
			Scorecard: sc, Cases: []*cases.Case{c},
			LocalIDs: map[string]bool{"engineering-review": true}, IssueBriefWriter: writer,
			PriorMisses: []MissEvidence{
				{Package: "engineering-review", Summary: "The coverage reaches the branch without asserting the invariant.", PRURL: "https://github.com/acme/two/pull/2"},
				{Package: "engineering-review", Summary: "The newly supported value is still rejected by a downstream adapter.", PRURL: "https://github.com/acme/three/pull/3"},
			},
		})
	}()
	select {
	case issues := <-done:
		if len(issues) != 2 {
			t.Fatalf("issues=%d %#v", len(issues), issues)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("issue briefs were generated serially")
	}
}
