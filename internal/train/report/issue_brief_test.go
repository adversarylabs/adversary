package report

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/adversarylabs/adversary/internal/modelreview"
	"github.com/adversarylabs/adversary/internal/train/cases"
	"github.com/adversarylabs/adversary/internal/train/judge"
	"github.com/adversarylabs/adversary/internal/train/score"
)

type fixtureBriefProvider struct {
	request modelreview.Request
}

func (p *fixtureBriefProvider) Name() string  { return "fixture" }
func (p *fixtureBriefProvider) Model() string { return "fixture" }
func (p *fixtureBriefProvider) Review(_ context.Context, request modelreview.Request) (modelreview.Result, error) {
	p.request = request
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
