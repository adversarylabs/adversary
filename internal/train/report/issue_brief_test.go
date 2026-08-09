package report

import (
	"context"
	"encoding/json"
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
		!strings.Contains(provider.request.Prompt, "same causal mechanism") {
		t.Fatalf("prompt does not require evidence-grounded generalization:\n%s", provider.request.Prompt)
	}
	if !strings.Contains(string(provider.request.Input), "Staff-level review") {
		t.Fatalf("package scope missing from model input: %s", provider.request.Input)
	}
	rendered := renderIssueBrief(brief)
	for _, want := range []string{"What we want to improve", "Why this matters", "Examples", "Keep it focused", "Done when"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("rendered brief missing %q:\n%s", want, rendered)
		}
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

func TestSuggestIssuesUsesFullSourceCommentAsBriefEvidence(t *testing.T) {
	const fullComment = "This value is already masked on every path it takes. The trace manager masks logs and the issue recorder masks annotations. The new helper is only for protocol payloads that bypass both paths, so it is not applicable here."
	c := &cases.Case{
		ID:          "case-masking",
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

func TestSuggestIssuesUsesModelBriefAndPackageScope(t *testing.T) {
	c := &cases.Case{
		ID:          "case-1",
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
	})
	if len(issues) != 1 {
		t.Fatalf("issues=%d %#v", len(issues), issues)
	}
	if issues[0].Title != "Detect independent behavior hidden inside an otherwise focused change" {
		t.Fatalf("model title not used: %#v", issues[0])
	}
	if issues[0].Key != "engineering-review|general" {
		t.Fatalf("stable concern key missing: %#v", issues[0])
	}
	if strings.Contains(issues[0].Body, "Task for coding agent") || strings.Contains(issues[0].Body, "Example concern classes") {
		t.Fatalf("legacy boilerplate leaked into generated brief:\n%s", issues[0].Body)
	}
	if writer.input.PackageScope != "Staff-level residual engineering judgment." {
		t.Fatalf("scope not passed to writer: %#v", writer.input)
	}
	if len(writer.input.Evidence) != 1 || writer.input.Evidence[0].PRTitle != "fix operator precedence" {
		t.Fatalf("source context not passed to writer: %#v", writer.input)
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
		ID: "case-concurrent",
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
