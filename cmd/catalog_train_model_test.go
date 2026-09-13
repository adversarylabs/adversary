package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/internal/train/catalogapply"
)

type catalogModelRuntimeStub struct {
	config   application.ModelReviewConfig
	provider application.ModelReviewProvider
	err      error
}

func (s *catalogModelRuntimeStub) ModelReviewProvider(config application.ModelReviewConfig) (application.ModelReviewProvider, error) {
	s.config = config
	return s.provider, s.err
}

type catalogModelProviderStub struct {
	name, model string
	output      json.RawMessage
	outputs     []json.RawMessage
	requests    *[]application.ModelReviewRequest
}

func (s catalogModelProviderStub) Name() string  { return s.name }
func (s catalogModelProviderStub) Model() string { return s.model }
func (s catalogModelProviderStub) Review(_ context.Context, request application.ModelReviewRequest) (json.RawMessage, error) {
	if s.requests != nil {
		*s.requests = append(*s.requests, request)
	}
	if len(s.outputs) > 0 {
		output := s.outputs[0]
		s.outputs = s.outputs[1:]
		return output, nil
	}
	if len(s.output) > 0 {
		return s.output, nil
	}
	return json.RawMessage(`{"disposition":"noise"}`), nil
}

type catalogSequenceProviderStub struct {
	name, model string
	outputs     []json.RawMessage
	requests    []application.ModelReviewRequest
}

func (s *catalogSequenceProviderStub) Name() string  { return s.name }
func (s *catalogSequenceProviderStub) Model() string { return s.model }
func (s *catalogSequenceProviderStub) Review(_ context.Context, request application.ModelReviewRequest) (json.RawMessage, error) {
	s.requests = append(s.requests, request)
	if len(s.outputs) == 0 {
		return nil, errors.New("unexpected model call")
	}
	output := s.outputs[0]
	s.outputs = s.outputs[1:]
	return output, nil
}

func TestCatalogTriageModelSupportsCloudflareProvider(t *testing.T) {
	runtime := &catalogModelRuntimeStub{provider: catalogModelProviderStub{
		name: "cloudflare", model: "@cf/meta/llama-3.3-70b-instruct-fp8-fast",
	}}
	call, name, err := newCatalogTriageModel(context.Background(), runtime, "cloudflare", "@cf/meta/llama-3.3-70b-instruct-fp8-fast")
	if err != nil {
		t.Fatal(err)
	}
	if runtime.config.Provider != "cloudflare" || runtime.config.Model != "@cf/meta/llama-3.3-70b-instruct-fp8-fast" {
		t.Fatalf("config=%+v", runtime.config)
	}
	if call == nil || name != "cloudflare/@cf/meta/llama-3.3-70b-instruct-fp8-fast" {
		t.Fatalf("call=%v name=%q", call != nil, name)
	}
}

func TestCatalogReviewAssistDraftsBlankRule(t *testing.T) {
	runtime := &catalogModelRuntimeStub{provider: catalogModelProviderStub{
		name: "camel", model: "auto", output: json.RawMessage(`{"adversary":"operability","proposed_rule":"Include the tenant id in restore failure logs.","adversary_mission":"","rationale":"Private diagnostic convention."}`),
	}}
	result, err := catalogReviewAssist(runtime, "camel", "auto")(context.Background(), application.CatalogAssistRequest{
		Evidence: "log this error with the tenant", Adversaries: []string{"operability"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Adversary != "operability" || !strings.Contains(result.ProposedRule, "tenant id") {
		t.Fatalf("result=%+v", result)
	}
}

func TestCatalogTriageModelRequiresConfiguration(t *testing.T) {
	runtime := &catalogModelRuntimeStub{err: errors.New("ADVERSARY_MODEL is required")}
	_, _, err := newCatalogTriageModel(context.Background(), runtime, "", "")
	if err == nil || !strings.Contains(err.Error(), "--model-provider and --model") {
		t.Fatalf("missing model configuration error=%v", err)
	}
}

func TestCatalogChangePlannerUsesConfiguredModel(t *testing.T) {
	runtime := &catalogModelRuntimeStub{provider: catalogModelProviderStub{
		name: "camel", model: "auto", output: json.RawMessage(`{"summary":"add policy and regression","files":[{"path":"adversaries/operability/README.md","content":"# Operability"},{"path":"adversaries/operability/tests/candidate.yaml","content":"version: 1"}]}`),
	}}
	plan, err := catalogChangePlanner(runtime, "camel", "auto")(context.Background(), catalogapply.ChangeRequest{
		CandidateID: "candidate", Adversary: "operability", ProposedRule: "Show actionable errors.",
	})
	if err != nil {
		t.Fatal(err)
	}
	if runtime.config.Provider != "camel" || runtime.config.Model != "auto" || len(plan.Files) != 2 {
		t.Fatalf("config=%+v plan=%+v", runtime.config, plan)
	}
}

func TestCatalogChangePlannerExecutesManagedRegressionCases(t *testing.T) {
	plan := `{"summary":"Prevent hidden failures in operability","files":[{"path":"adversaries/operability/rules/actionable-errors/rule.yaml","content":"version: 1\nid: actionable-errors\nsummary: Show actionable failures\nguidance: Report hidden failures and allow errors with a recovery step.\nseverity: medium\nconfidence: high\nevidence: https://example.test/evidence\n"},{"path":"adversaries/operability/rules/actionable-errors/cases.yaml","content":"version: 1\nrule_id: actionable-errors\ncandidate_id: candidate\nevidence: https://example.test/evidence\ncases:\n  - name: hidden failure\n    review_input: the error is replaced by failed\n    expected: finding\n    reason: no recovery detail\n  - name: actionable failure\n    review_input: the error includes its cause and recovery step\n    expected: no_finding\n    reason: actionable\n"}]}`
	provider := &catalogSequenceProviderStub{name: "camel", model: "auto", outputs: []json.RawMessage{
		json.RawMessage(`{"disposition":"new_rule","adversary":"","rule_id":"","reason":"distinct behavior"}`),
		json.RawMessage(plan),
		json.RawMessage(`{"results":[{"name":"hidden failure","actual":"finding","reason":"hidden"},{"name":"actionable failure","actual":"no_finding","reason":"allowed"}]}`),
	}}
	runtime := &catalogModelRuntimeStub{provider: provider}
	got, err := catalogChangePlanner(runtime, "camel", "auto")(context.Background(), catalogapply.ChangeRequest{
		CandidateID: "candidate", Adversary: "operability", ManagedRuntime: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Files) != 2 || len(provider.requests) != 3 {
		t.Fatalf("plan=%+v model calls=%d", got, len(provider.requests))
	}
	if strings.Contains(string(provider.requests[2].Input), "expected") {
		t.Fatalf("case evaluator leaked expected answers: %s", provider.requests[2].Input)
	}
}

func TestCatalogChangePlannerRejectsManagedRegressionMismatch(t *testing.T) {
	plan := `{"summary":"Prevent hidden failures in operability","files":[{"path":"adversaries/operability/rules/actionable-errors/rule.yaml","content":"version: 1\nid: actionable-errors\nsummary: Show actionable failures\nguidance: Report hidden failures.\n"},{"path":"adversaries/operability/rules/actionable-errors/cases.yaml","content":"version: 1\nrule_id: actionable-errors\ncases:\n  - name: hidden failure\n    review_input: an actionable error is returned\n    expected: finding\n    reason: claimed regression\n"}]}`
	provider := &catalogSequenceProviderStub{name: "camel", model: "auto", outputs: []json.RawMessage{
		json.RawMessage(`{"disposition":"new_rule","adversary":"","rule_id":"","reason":"distinct behavior"}`),
		json.RawMessage(plan), json.RawMessage(`{"results":[{"name":"hidden failure","actual":"no_finding","reason":"the rule does not match"}]}`),
	}}
	runtime := &catalogModelRuntimeStub{provider: provider}
	_, err := catalogChangePlanner(runtime, "camel", "auto")(context.Background(), catalogapply.ChangeRequest{ManagedRuntime: 3})
	if err == nil || !strings.Contains(err.Error(), "executable regression cases failed") {
		t.Fatalf("err=%v", err)
	}
}

func TestCatalogChangePlannerStopsWhenCatalogAlreadyCoversCandidate(t *testing.T) {
	provider := &catalogSequenceProviderStub{name: "camel", model: "auto", outputs: []json.RawMessage{
		json.RawMessage(`{"disposition":"already_covered","adversary":"operability","rule_id":"actionable-errors","reason":"It checks the same hidden-error condition."}`),
	}}
	runtime := &catalogModelRuntimeStub{provider: provider}
	_, err := catalogChangePlanner(runtime, "camel", "auto")(context.Background(), catalogapply.ChangeRequest{
		ManagedRuntime: 3, ProposedRule: "Do not hide errors.", CatalogPolicies: []catalogapply.SourceFile{{Path: "adversaries/operability/rules/actionable-errors/rule.yaml", Content: "guidance: Report hidden errors."}},
	})
	if err == nil || !strings.Contains(err.Error(), "already covered by operability/actionable-errors") || !strings.Contains(err.Error(), "no catalog pull request") {
		t.Fatalf("err=%v", err)
	}
	if len(provider.requests) != 1 {
		t.Fatalf("model calls=%d want 1", len(provider.requests))
	}
}
