package githubreview

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/adversarylabs/adversary/internal/modelreview"
	"github.com/adversarylabs/adversary/pkg/review"
)

type fakeProvider struct {
	name  string
	model string
	// bodies maps finding id -> rewrite body (JSON object without outer schema wrap handled by Review)
	bodies map[string]string
	calls  int
	fail   bool
}

func (f *fakeProvider) Name() string  { return f.name }
func (f *fakeProvider) Model() string { return f.model }

func (f *fakeProvider) Review(_ context.Context, req modelreview.Request) (modelreview.Result, error) {
	f.calls++
	if f.fail {
		return modelreview.Result{}, &modelreview.ProviderError{Code: "fail", Message: "provider down"}
	}
	if !strings.Contains(req.Prompt, "Adversary Labs") && !strings.Contains(req.Prompt, "Custom") {
		return modelreview.Result{}, &modelreview.ProviderError{Code: "bad_prompt", Message: "missing voice prompt"}
	}
	var in struct {
		FindingID string `json:"findingId"`
	}
	if err := json.Unmarshal(req.Input, &in); err != nil {
		return modelreview.Result{}, err
	}
	body, ok := f.bodies[in.FindingID]
	if !ok {
		body = "Rewritten: " + in.FindingID
	}
	out, _ := json.Marshal(map[string]string{"body": body})
	return modelreview.Result{Output: out}, nil
}

func TestEnhanceBodiesUsesProviderAndSetsLLMSource(t *testing.T) {
	line := 3
	env := review.RunEnvelope{
		ProtocolVersion: 1,
		Result: review.ReviewResult{
			Adversary: review.ReviewAdversary{Name: "go-cli"},
			Positives: []review.Note{}, Observations: []review.Note{},
			Findings: []review.Finding{{
				ID: "f1", Title: "Issue", Category: "c", Severity: "high", Confidence: "high",
				Summary: "raw summary", Evidence: []review.Evidence{{File: "a.go", Line: &line}},
				Recommendation: "fix",
			}},
			Suppressed: review.Suppressed{},
		},
	}
	plan := ProjectFindings([]NamedEnvelope{{Adversary: "go-cli", Envelope: env}}, ProjectOptions{
		Voice: VoiceInfo{Source: "cli_default"},
	})
	if plan.Comments[0].BodySource != "template" {
		t.Fatalf("pre-enhance: %s", plan.Comments[0].BodySource)
	}
	fp := &fakeProvider{
		name: "fake", model: "m",
		bodies: map[string]string{"f1": "Concise rewrite of the issue."},
	}
	EnhanceBodies(context.Background(), &plan, EnhanceOptions{
		Provider:    fp,
		VoicePrompt: DefaultVoicePrompt,
	})
	if fp.calls != 1 {
		t.Fatalf("calls %d", fp.calls)
	}
	if plan.Comments[0].BodySource != "llm" {
		t.Fatalf("source %s", plan.Comments[0].BodySource)
	}
	if !strings.Contains(plan.Comments[0].Body, "Concise rewrite") {
		t.Fatal(plan.Comments[0].Body)
	}
	if !strings.Contains(plan.Comments[0].Body, "adversary-review:v1") {
		t.Fatal("marker missing after enhance")
	}
}

func TestEnhanceBodiesFallsBackOnProviderFailure(t *testing.T) {
	line := 1
	env := review.RunEnvelope{
		ProtocolVersion: 1,
		Result: review.ReviewResult{
			Adversary:    review.ReviewAdversary{Name: "x"},
			Positives:    []review.Note{},
			Observations: []review.Note{},
			Findings: []review.Finding{{
				ID: "f1", Title: "T", Category: "c", Severity: "high", Confidence: "high",
				Summary: "s", Evidence: []review.Evidence{{File: "a.go", Line: &line}},
			}},
			Suppressed: review.Suppressed{},
		},
	}
	plan := ProjectFindings([]NamedEnvelope{{Adversary: "x", Envelope: env}}, ProjectOptions{})
	before := plan.Comments[0].Body
	fp := &fakeProvider{fail: true, bodies: map[string]string{}}
	EnhanceBodies(context.Background(), &plan, EnhanceOptions{
		Provider:    fp,
		VoicePrompt: DefaultVoicePrompt,
	})
	if plan.Comments[0].BodySource != "template" {
		t.Fatalf("%s", plan.Comments[0].BodySource)
	}
	if plan.Comments[0].Body != before {
		t.Fatal("template body should be preserved")
	}
}

func TestEnhanceBodiesNoopWithoutProvider(t *testing.T) {
	plan := CommentPlan{Comments: []PlannedComment{{
		FindingID: "f", Body: "template", BodySource: "template", Placement: "inline",
	}}}
	EnhanceBodies(context.Background(), &plan, EnhanceOptions{VoicePrompt: DefaultVoicePrompt})
	if plan.Comments[0].BodySource != "template" {
		t.Fatal(plan.Comments[0].BodySource)
	}
}

func TestEnhanceBodiesUsesRepoVoicePrompt(t *testing.T) {
	line := 2
	env := review.RunEnvelope{
		ProtocolVersion: 1,
		Result: review.ReviewResult{
			Adversary: review.ReviewAdversary{Name: "x"},
			Positives: []review.Note{}, Observations: []review.Note{},
			Findings: []review.Finding{{
				ID: "f1", Title: "T", Category: "c", Severity: "medium", Confidence: "high",
				Summary: "s", Evidence: []review.Evidence{{File: "a.go", Line: &line}},
			}},
			Suppressed: review.Suppressed{},
		},
	}
	plan := ProjectFindings([]NamedEnvelope{{Adversary: "x", Envelope: env}}, ProjectOptions{
		Voice: VoiceInfo{Source: "repo", Path: "VOICE.md"},
	})
	fp := &fakeProvider{bodies: map[string]string{"f1": "Acme voice rewrite."}}
	EnhanceBodies(context.Background(), &plan, EnhanceOptions{
		Provider:    fp,
		VoicePrompt: "Custom Acme voice for PR comments",
	})
	if plan.Comments[0].BodySource != "llm" || !strings.Contains(plan.Comments[0].Body, "Acme voice") {
		t.Fatalf("%#v", plan.Comments[0])
	}
}
