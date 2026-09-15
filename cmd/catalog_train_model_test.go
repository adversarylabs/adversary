package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

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
	err         error
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
	if s.err != nil {
		return nil, s.err
	}
	if len(s.output) > 0 {
		return s.output, nil
	}
	return json.RawMessage(`{"disposition":"noise"}`), nil
}

func TestCatalogOverlapPreservesContextCancellation(t *testing.T) {
	wrapped := fmt.Errorf("provider stopped: %w", context.Canceled)
	runtime := &catalogModelRuntimeStub{provider: catalogModelProviderStub{name: "camel", model: "auto", err: wrapped}}
	_, err := catalogChangePlanner(runtime, "camel", "auto")(context.Background(), catalogapply.ChangeRequest{ManagedRuntime: 1})
	if !errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "check current catalog") {
		t.Fatalf("cancellation was reclassified: %v", err)
	}
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
		json.RawMessage(`{"assessments":[{"strategy":"model","confidence":"high","deterministic_value":"none","reason":"semantic judgment only"},{"strategy":"model","confidence":"high","deterministic_value":"none","reason":"no stable repository signal"}]}`),
		json.RawMessage(plan),
		json.RawMessage(`{"disposition":"accept","reason":"The rule is scoped to the demonstrated condition and its close exception."}`),
		json.RawMessage(`{"results":[{"name":"hidden failure","actual":"finding","reason":"hidden"},{"name":"actionable failure","actual":"no_finding","reason":"allowed"}]}`),
	}}
	runtime := &catalogModelRuntimeStub{provider: provider}
	got, err := catalogChangePlanner(runtime, "camel", "auto")(context.Background(), catalogapply.ChangeRequest{
		CandidateID: "candidate", Adversary: "operability", ManagedRuntime: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Files) != 2 || got.Strategy != catalogapply.StrategyModelBacked || len(provider.requests) != 5 {
		t.Fatalf("plan=%+v model calls=%d", got, len(provider.requests))
	}
	if strings.Contains(string(provider.requests[4].Input), "expected") {
		t.Fatalf("case evaluator leaked expected answers: %s", provider.requests[4].Input)
	}
}

func TestCatalogChangePlannerAllowsExplicitOverlapOverride(t *testing.T) {
	plan := `{"summary":"Prevent hidden failures in operability","files":[{"path":"adversaries/operability/rules/actionable-errors/rule.yaml","content":"version: 1\nid: actionable-errors\nsummary: Show actionable failures\nguidance: Report hidden failures and allow errors with a recovery step.\nseverity: medium\nconfidence: high\nevidence: https://example.test/evidence\n"},{"path":"adversaries/operability/rules/actionable-errors/cases.yaml","content":"version: 1\nrule_id: actionable-errors\ncandidate_id: candidate\nevidence: https://example.test/evidence\ncases:\n  - name: hidden failure\n    review_input: hidden error\n    expected: finding\n    reason: hidden\n  - name: actionable failure\n    review_input: error with recovery\n    expected: no_finding\n    reason: actionable\n"}]}`
	provider := &catalogSequenceProviderStub{name: "camel", model: "auto", outputs: []json.RawMessage{
		json.RawMessage(`{"assessments":[{"strategy":"model","confidence":"high","deterministic_value":"none","reason":"semantic"},{"strategy":"model","confidence":"high","deterministic_value":"none","reason":"semantic"}]}`),
		json.RawMessage(plan),
		json.RawMessage(`{"disposition":"accept","reason":"Scoped."}`),
		json.RawMessage(`{"results":[{"name":"hidden failure","actual":"finding","reason":"hidden"},{"name":"actionable failure","actual":"no_finding","reason":"allowed"}]}`),
	}}
	runtime := &catalogModelRuntimeStub{provider: provider}
	got, err := catalogChangePlanner(runtime, "camel", "auto")(context.Background(), catalogapply.ChangeRequest{
		CandidateID: "candidate", Adversary: "operability", Evidence: "https://example.test/evidence", ManagedRuntime: 1, AllowOverlap: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Strategy != catalogapply.StrategyModelBacked || len(provider.requests) != 4 || strings.Contains(provider.requests[0].Prompt, "already substantively enforced") {
		t.Fatalf("plan=%+v requests=%d", got, len(provider.requests))
	}
}

func TestCatalogStrategyDefaultsToDeterministicOnDisagreement(t *testing.T) {
	provider := &catalogSequenceProviderStub{name: "camel", model: "auto", outputs: []json.RawMessage{
		json.RawMessage(`{"assessments":[{"strategy":"model","confidence":"high","deterministic_value":"none","reason":"mostly semantic"},{"strategy":"deterministic","confidence":"medium","deterministic_value":"possible","reason":"a path invariant may be checked"}]}`),
	}}
	strategy, err := selectCatalogStrategy(context.Background(), provider, json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if strategy != catalogapply.StrategyDeterministic {
		t.Fatalf("strategy=%q", strategy)
	}
}

func TestCatalogChangePlannerFallsBackToDeterministicWhenClassificationIsUncertain(t *testing.T) {
	provider := &catalogSequenceProviderStub{name: "camel", model: "auto", outputs: []json.RawMessage{
		json.RawMessage(`{"disposition":"new_rule","adversary":"","rule_id":"","reason":"distinct"}`),
		json.RawMessage(`{"not_assessments":[]}`),
		json.RawMessage(`{"summary":"Enforce concrete paths in operability","files":[{"path":"adversaries/operability/README.md","content":"# Operability\n"},{"path":"adversaries/operability/src/deterministic.ts","content":"export function registerDeterministicRules() {}\n"}]}`),
		json.RawMessage(`{"disposition":"accept","reason":"The deterministic implementation and runtime cases are properly scoped."}`),
		json.RawMessage(`{"disposition":"accept","reason":"The independent red-team pass found no missing association."}`),
	}}
	runtime := &catalogModelRuntimeStub{provider: provider}
	plan, err := catalogChangePlanner(runtime, "camel", "auto")(context.Background(), catalogapply.ChangeRequest{ManagedRuntime: 1})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Strategy != catalogapply.StrategyDeterministic || len(provider.requests) != 5 {
		t.Fatalf("plan=%+v calls=%d", plan, len(provider.requests))
	}
}

func TestCatalogChangePlannerRejectsOverbroadManagedRule(t *testing.T) {
	plan := `{"summary":"Prevent hidden failures in operability","files":[{"path":"adversaries/operability/rules/actionable-errors/rule.yaml","content":"version: 1\nid: actionable-errors\nsummary: Show actionable failures\nguidance: Report every error.\nseverity: high\nconfidence: high\nevidence: https://example.test/evidence\n"},{"path":"adversaries/operability/rules/actionable-errors/cases.yaml","content":"version: 1\nrule_id: actionable-errors\ncandidate_id: candidate\nevidence: https://example.test/evidence\ncases:\n  - name: hidden failure\n    review_input: the error is replaced by failed\n    expected: finding\n    reason: no recovery detail\n  - name: actionable failure\n    review_input: the error includes its cause and recovery step\n    expected: no_finding\n    reason: actionable\n"}]}`
	provider := &catalogSequenceProviderStub{name: "camel", model: "auto", outputs: []json.RawMessage{
		json.RawMessage(`{"disposition":"new_rule","adversary":"","rule_id":"","reason":"distinct behavior"}`),
		json.RawMessage(`{"assessments":[{"strategy":"model","confidence":"high","deterministic_value":"none","reason":"semantic judgment only"},{"strategy":"model","confidence":"high","deterministic_value":"none","reason":"no stable repository signal"}]}`),
		json.RawMessage(plan),
		json.RawMessage(`{"disposition":"revise","reason":"The guidance expands one hidden-error example into every error and does not encode the allowed case."}`),
	}}
	runtime := &catalogModelRuntimeStub{provider: provider}
	_, err := catalogChangePlanner(runtime, "camel", "auto")(context.Background(), catalogapply.ChangeRequest{ManagedRuntime: 1})
	if err == nil || !strings.Contains(err.Error(), "rule quality review requested revision") {
		t.Fatalf("err=%v", err)
	}
}

func TestCatalogChangePlannerRejectsPathOnlyDeterministicRule(t *testing.T) {
	provider := &catalogSequenceProviderStub{name: "camel", model: "auto", outputs: []json.RawMessage{
		json.RawMessage(`{"disposition":"new_rule","adversary":"","rule_id":"","reason":"distinct behavior"}`),
		json.RawMessage(`{"assessments":[{"strategy":"deterministic","confidence":"high","deterministic_value":"clear","reason":"observable source pattern"},{"strategy":"deterministic","confidence":"high","deterministic_value":"clear","reason":"a close source counterexample is available"}]}`),
		json.RawMessage(`{"summary":"Prevent poisoned initialization in reliability","files":[{"path":"adversaries/reliability/README.md","content":"# Reliability\n"},{"path":"adversaries/reliability/src/deterministic.ts","content":"export function registerDeterministicRules() {}\n"},{"path":"adversaries/reliability/src/rules/lazy.ts","content":"export function review(ctx) { if (ctx.change.changedFiles.includes('resolver.go')) ctx.finding({}); }\n"},{"path":"adversaries/reliability/test/lazy.test.ts","content":"import { createApp } from '../src/index.ts'; void createApp();\n"}]}`),
		json.RawMessage(`{"disposition":"revise","reason":"The implementation is an evidence-path tripwire and the test never executes the registered rule."}`),
	}}
	runtime := &catalogModelRuntimeStub{provider: provider}
	got, err := catalogChangePlanner(runtime, "camel", "auto")(context.Background(), catalogapply.ChangeRequest{ManagedRuntime: 1, EvidenceFile: "resolver.go"})
	if err == nil || !strings.Contains(err.Error(), "deterministic quality review requested revision") {
		t.Fatalf("err=%v", err)
	}
	if len(got.Files) != 4 || !strings.Contains(got.Files[2].Content, "resolver.go") {
		t.Fatalf("rejected plan was not returned for repair: %+v", got)
	}
}

func TestCatalogChangePlannerRetainsDecisionsDuringQualityRepair(t *testing.T) {
	provider := &catalogSequenceProviderStub{name: "camel", model: "auto", outputs: []json.RawMessage{
		json.RawMessage(`{"summary":"Prevent poisoned initialization in reliability","files":[{"path":"adversaries/reliability/src/rules/lazy.ts","content":"export async function review(ctx) { const sources = await ctx.loadInScopeSources(); void sources; }\n"}]}`),
		json.RawMessage(`{"disposition":"accept","reason":"The repaired implementation is scoped and exercised through production."}`),
		json.RawMessage(`{"disposition":"accept","reason":"The red-team pass found no material counterexample."}`),
	}}
	runtime := &catalogModelRuntimeStub{provider: provider}
	var updates []catalogapply.Progress
	previous := &catalogapply.ChangePlan{Strategy: catalogapply.StrategyDeterministic, Files: []catalogapply.ChangeFile{
		{Path: "adversaries/reliability/README.md", Content: "# Reliability\n"},
		{Path: "adversaries/reliability/src/deterministic.ts", Content: "export function registerDeterministicRules() {}\n"},
		{Path: "adversaries/reliability/src/rules/lazy.ts", Content: "// rejected"},
		{Path: "adversaries/reliability/test/lazy.test.ts", Content: "import { createApp } from '../src/index.ts'; void createApp().run({});\n"},
	}}
	plan, err := catalogChangePlanner(runtime, "camel", "auto")(context.Background(), catalogapply.ChangeRequest{
		ManagedRuntime: 1, GenerationAttempt: 2, MaxGenerationTurns: 3, PreviousPlan: previous,
		RepairStage: "build_and_test", ValidationFeedback: "Replace the brittle matcher.", Progress: func(update catalogapply.Progress) { updates = append(updates, update) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Strategy != catalogapply.StrategyDeterministic || len(provider.requests) != 3 {
		t.Fatalf("plan=%+v model calls=%d want generation and two critics", plan, len(provider.requests))
	}
	if len(plan.Files) != 4 || plan.Files[0].Content != previous.Files[0].Content || plan.Files[1].Content != previous.Files[1].Content || plan.Files[3].Content != previous.Files[3].Content {
		t.Fatalf("repair did not retain unchanged files byte-for-byte: %+v", plan.Files)
	}
	if !strings.Contains(plan.Files[2].Content, "loadInScopeSources") {
		t.Fatalf("repair did not replace the changed file: %+v", plan.Files[2])
	}
	if !strings.Contains(provider.requests[0].Prompt, "Omitted previous files are retained and merged locally") {
		t.Fatalf("repair prompt did not describe delta responses: %s", provider.requests[0].Prompt)
	}
	details := ""
	for _, update := range updates {
		details += update.Detail + "\n"
	}
	for _, want := range []string{"Existing coverage decision retained", "Coverage strategy retained", "attempt 2 of 3"} {
		if !strings.Contains(details, want) {
			t.Fatalf("progress omitted %q:\n%s", want, details)
		}
	}
}

func TestNormalizeCatalogPlanFilesDropsModelBundlesFromDeterministicPlans(t *testing.T) {
	files := []catalogapply.ChangeFile{
		{Path: "adversaries/reliability/rules/lazy/rule.yaml"},
		{Path: "adversaries/reliability/src/rules/lazy.ts"},
		{Path: "adversaries/reliability/test/lazy.test.ts"},
	}
	got := normalizeCatalogPlanFiles(catalogapply.StrategyDeterministic, files)
	if len(got) != 2 || !strings.Contains(got[0].Path, "/src/rules/") {
		t.Fatalf("normalized files=%+v", got)
	}
}

func TestCatalogChangePlannerReplacesPlanDuringStructuralRepair(t *testing.T) {
	provider := &catalogSequenceProviderStub{name: "camel", model: "auto", outputs: []json.RawMessage{
		json.RawMessage(`{"summary":"Prevent poisoned initialization in reliability","files":[{"path":"adversaries/reliability/src/rules/lazy.ts","content":"export async function review(ctx) { void ctx; }\n"},{"path":"adversaries/reliability/test/lazy.test.ts","content":"import { createApp } from '../src/index.ts'; void createApp();\n"}]}`),
		json.RawMessage(`{"disposition":"accept","reason":"The corrected plan removed the forbidden bundle."}`),
		json.RawMessage(`{"disposition":"accept","reason":"The red-team pass found no material counterexample."}`),
	}}
	runtime := &catalogModelRuntimeStub{provider: provider}
	previous := &catalogapply.ChangePlan{Strategy: catalogapply.StrategyDeterministic, Files: []catalogapply.ChangeFile{
		{Path: "adversaries/reliability/rules/lazy.yaml", Content: "forbidden"},
		{Path: "adversaries/reliability/src/rules/lazy.ts", Content: "// rejected"},
		{Path: "adversaries/reliability/test/lazy.test.ts", Content: "// rejected"},
	}}
	plan, err := catalogChangePlanner(runtime, "camel", "auto")(context.Background(), catalogapply.ChangeRequest{
		ManagedRuntime: 1, GenerationAttempt: 2, MaxGenerationTurns: 3, PreviousPlan: previous,
		RepairStage: "plan_validation", ValidationFeedback: "Remove the model-backed bundle.",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Files) != 2 {
		t.Fatalf("structural repair retained rejected files: %+v", plan.Files)
	}
	for _, file := range plan.Files {
		if strings.HasSuffix(file.Path, ".yaml") {
			t.Fatalf("structural repair retained forbidden file: %+v", file)
		}
	}
}

func TestCatalogChangePlannerUsesFocusedBuildAndTestRepairPrompt(t *testing.T) {
	provider := &catalogSequenceProviderStub{name: "camel", model: "auto", outputs: []json.RawMessage{
		json.RawMessage(`{"summary":"Prevent poisoned initialization in reliability","files":[{"path":"adversaries/reliability/README.md","content":"# Reliability\n"},{"path":"adversaries/reliability/src/deterministic.ts","content":"export function registerDeterministicRules() {}\n"},{"path":"adversaries/reliability/src/rules/lazy.ts","content":"export async function review(ctx) { const sources = await ctx.loadInScopeSources(); void sources; }\n"},{"path":"adversaries/reliability/test/lazy.test.ts","content":"import { createApp } from '../src/index.ts'; void createApp().run({ input: { source: { path: fixtureDirectory } } });\n"}]}`),
		json.RawMessage(`{"disposition":"accept","reason":"The matcher and close counterexample are aligned."}`),
		json.RawMessage(`{"disposition":"accept","reason":"The red-team pass found no material counterexample."}`),
	}}
	runtime := &catalogModelRuntimeStub{provider: provider}
	previous := &catalogapply.ChangePlan{Strategy: catalogapply.StrategyDeterministic, Files: []catalogapply.ChangeFile{{Path: "adversaries/reliability/src/rules/lazy.ts", Content: "// matcher that missed the positive fixture"}}}
	_, err := catalogChangePlanner(runtime, "camel", "auto")(context.Background(), catalogapply.ChangeRequest{
		ManagedRuntime: 1, GenerationAttempt: 4, MaxGenerationTurns: 6, MaxQualityTurns: 3,
		PreviousPlan: previous, RepairStage: "build_and_test",
		ProposedRule: "Detect stale cached initialization failures", EvidenceComment: "A transient initialization failure remains cached",
		ValidationFeedback: "old critic feedback", LatestFeedback: "expected a lazy-initialization finding",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(provider.requests) != 3 {
		t.Fatalf("model calls=%d want generation and two critics", len(provider.requests))
	}
	prompt := provider.requests[0].Prompt
	for _, want := range []string{"VALIDATION REPAIR MODE", "Do not weaken the assertion", "remove invented SDK options", "registered rule dispatch", "review-scope filtering", "semanticMatches-based design", "without interpreting the query", "repair the stale test assertion"} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("repair prompt omitted %q:\n%s", want, prompt)
		}
	}
	if !strings.Contains(string(provider.requests[0].Input), `"latest_validation_feedback":"expected a lazy-initialization finding"`) {
		t.Fatalf("repair input omitted latest failure: %s", provider.requests[0].Input)
	}
}

func TestNormalizeCatalogSummaryAddsMissingAdversary(t *testing.T) {
	got := normalizeCatalogSummary("Prevent poisoned one-shot initialization", "reliability-and-concurrency", 120)
	want := "Prevent poisoned one-shot initialization in reliability-and-concurrency"
	if got != want {
		t.Fatalf("normalizeCatalogSummary() = %q, want %q", got, want)
	}
}

func TestCatalogChangePlannerTreatsFinalCriticRevisionAsAdvisory(t *testing.T) {
	provider := &catalogSequenceProviderStub{name: "camel", model: "auto", outputs: []json.RawMessage{
		json.RawMessage(`{"summary":"Prevent poisoned initialization in reliability","files":[{"path":"adversaries/reliability/README.md","content":"# Reliability\n"},{"path":"adversaries/reliability/src/deterministic.ts","content":"export function registerDeterministicRules() {}\n"},{"path":"adversaries/reliability/src/rules/lazy.ts","content":"export async function review(ctx) { const sources = await ctx.loadInScopeSources(); void sources; }\n"},{"path":"adversaries/reliability/test/lazy.test.ts","content":"import { createApp } from '../src/index.ts'; void createApp().run({});\n"}]}`),
		json.RawMessage(`{"disposition":"revise","reason":"A hypothetical uncommon syntax could be missed."}`),
	}}
	runtime := &catalogModelRuntimeStub{provider: provider}
	var updates []catalogapply.Progress
	previous := &catalogapply.ChangePlan{Strategy: catalogapply.StrategyDeterministic, Files: []catalogapply.ChangeFile{{Path: "adversaries/reliability/src/rules/lazy.ts", Content: "// second attempt"}}}
	plan, err := catalogChangePlanner(runtime, "camel", "auto")(context.Background(), catalogapply.ChangeRequest{
		ManagedRuntime: 1, GenerationAttempt: 2, MaxGenerationTurns: 5, MaxQualityTurns: 2, PreviousPlan: previous,
		ValidationFeedback: "One final correction.", Progress: func(update catalogapply.Progress) { updates = append(updates, update) },
	})
	if err != nil || plan.Strategy != catalogapply.StrategyDeterministic {
		t.Fatalf("plan=%+v err=%v", plan, err)
	}
	found := false
	for _, update := range updates {
		found = found || strings.Contains(update.Detail, "proceeding to compiler and runtime validation")
	}
	if !found {
		t.Fatalf("progress did not explain final critic disposition: %+v", updates)
	}
}

func TestCatalogChangePlannerKeepsUnsafeCriticRejectionBlocking(t *testing.T) {
	provider := &catalogSequenceProviderStub{name: "camel", model: "auto", outputs: []json.RawMessage{
		json.RawMessage(`{"summary":"Prevent poisoned initialization in reliability","files":[{"path":"adversaries/reliability/README.md","content":"# Reliability\n"},{"path":"adversaries/reliability/src/deterministic.ts","content":"export function registerDeterministicRules() {}\n"},{"path":"adversaries/reliability/src/rules/lazy.ts","content":"export async function review(ctx) { const sources = await ctx.loadInScopeSources(); void sources; }\n"},{"path":"adversaries/reliability/test/lazy.test.ts","content":"import { createApp } from '../src/index.ts'; void createApp().run({ input: { source: { path: fixtureDirectory } } });\n"}]}`),
		json.RawMessage(`{"disposition":"reject","reason":"The matcher combines unrelated file-wide tokens and the tests have no decoy case."}`),
	}}
	runtime := &catalogModelRuntimeStub{provider: provider}
	previous := &catalogapply.ChangePlan{Strategy: catalogapply.StrategyDeterministic, Files: []catalogapply.ChangeFile{{Path: "adversaries/reliability/src/rules/lazy.ts", Content: "// second attempt"}}}
	_, err := catalogChangePlanner(runtime, "camel", "auto")(context.Background(), catalogapply.ChangeRequest{
		ManagedRuntime: 1, GenerationAttempt: 1, MaxGenerationTurns: 5, MaxQualityTurns: 2, PreviousPlan: previous,
		ValidationFeedback: "One final correction.",
	})
	if err == nil || !strings.Contains(err.Error(), "rejected unsafe plan") {
		t.Fatalf("unsafe critic rejection became advisory: %v", err)
	}
}

func TestCatalogChangePlannerKeepsRedTeamRejectionBlocking(t *testing.T) {
	provider := &catalogSequenceProviderStub{name: "camel", model: "auto", outputs: []json.RawMessage{
		json.RawMessage(`{"summary":"Prevent poisoned initialization in reliability","files":[{"path":"adversaries/reliability/README.md","content":"# Reliability\n"},{"path":"adversaries/reliability/src/deterministic.ts","content":"export function registerDeterministicRules() {}\n"},{"path":"adversaries/reliability/src/rules/lazy.ts","content":"export async function review(ctx) { const sources = await ctx.loadInScopeSources(); void sources; }\n"},{"path":"adversaries/reliability/test/lazy.test.ts","content":"import { createApp } from '../src/index.ts'; void createApp().run({ input: { source: { path: fixtureDirectory } } });\n"}]}`),
		json.RawMessage(`{"disposition":"accept","reason":"The primary review found the plan acceptable."}`),
		json.RawMessage(`{"disposition":"reject","reason":"The scanner combines tokens from unrelated regions and produces a false positive."}`),
	}}
	runtime := &catalogModelRuntimeStub{provider: provider}
	previous := &catalogapply.ChangePlan{Strategy: catalogapply.StrategyDeterministic, Files: []catalogapply.ChangeFile{{Path: "adversaries/reliability/src/rules/lazy.ts", Content: "// second attempt"}}}
	_, err := catalogChangePlanner(runtime, "camel", "auto")(context.Background(), catalogapply.ChangeRequest{
		ManagedRuntime: 1, GenerationAttempt: 1, MaxGenerationTurns: 5, MaxQualityTurns: 2, PreviousPlan: previous,
		ValidationFeedback: "One final correction.",
	})
	if err == nil || !strings.Contains(err.Error(), "rejected unsafe plan") {
		t.Fatalf("red-team rejection became advisory: %v", err)
	}
	if len(provider.requests) != 3 || !strings.Contains(provider.requests[2].Prompt, "concrete semantic result") {
		t.Fatalf("red-team review was not executed with the semantic-query contract: %+v", provider.requests)
	}
}

func TestCatalogChangePlannerShortensSlightlyOverlongSummaryLocally(t *testing.T) {
	summary := "Prevent permanently cached dependency initialization failures from blocking retries across all resolver paths in operability"
	provider := &catalogSequenceProviderStub{name: "camel", model: "auto", outputs: []json.RawMessage{
		json.RawMessage(fmt.Sprintf(`{"summary":%q,"files":[{"path":"adversaries/operability/README.md","content":"# Operability\n"},{"path":"adversaries/operability/test/rule.test.ts","content":"// test\n"}]}`, summary)),
	}}
	runtime := &catalogModelRuntimeStub{provider: provider}
	plan, err := catalogChangePlanner(runtime, "camel", "auto")(context.Background(), catalogapply.ChangeRequest{Adversary: "operability"})
	if err != nil {
		t.Fatal(err)
	}
	if utf8.RuneCountInString(plan.Summary) > 120 || !strings.Contains(plan.Summary, "operability") {
		t.Fatalf("normalized summary=%q length=%d", plan.Summary, utf8.RuneCountInString(plan.Summary))
	}
}

func TestCatalogChangePlannerRejectsManagedRegressionMismatch(t *testing.T) {
	plan := `{"summary":"Prevent hidden failures in operability","files":[{"path":"adversaries/operability/rules/actionable-errors/rule.yaml","content":"version: 1\nid: actionable-errors\nsummary: Show actionable failures\nguidance: Report hidden failures.\n"},{"path":"adversaries/operability/rules/actionable-errors/cases.yaml","content":"version: 1\nrule_id: actionable-errors\ncases:\n  - name: hidden failure\n    review_input: an actionable error is returned\n    expected: finding\n    reason: claimed regression\n"}]}`
	provider := &catalogSequenceProviderStub{name: "camel", model: "auto", outputs: []json.RawMessage{
		json.RawMessage(`{"disposition":"new_rule","adversary":"","rule_id":"","reason":"distinct behavior"}`),
		json.RawMessage(`{"assessments":[{"strategy":"model","confidence":"high","deterministic_value":"none","reason":"semantic judgment only"},{"strategy":"model","confidence":"high","deterministic_value":"none","reason":"no stable repository signal"}]}`),
		json.RawMessage(plan),
		json.RawMessage(`{"disposition":"accept","reason":"The scope is supported."}`),
		json.RawMessage(`{"results":[{"name":"hidden failure","actual":"no_finding","reason":"the rule does not match"}]}`),
	}}
	runtime := &catalogModelRuntimeStub{provider: provider}
	_, err := catalogChangePlanner(runtime, "camel", "auto")(context.Background(), catalogapply.ChangeRequest{ManagedRuntime: 1})
	if err == nil || !strings.Contains(err.Error(), "semantic regression cases failed") {
		t.Fatalf("err=%v", err)
	}
}

func TestCatalogChangePlannerStopsWhenCatalogAlreadyCoversCandidate(t *testing.T) {
	provider := &catalogSequenceProviderStub{name: "camel", model: "auto", outputs: []json.RawMessage{
		json.RawMessage(`{"disposition":"already_covered","adversary":"operability","rule_id":"actionable-errors","reason":"It checks the same hidden-error condition."}`),
	}}
	runtime := &catalogModelRuntimeStub{provider: provider}
	_, err := catalogChangePlanner(runtime, "camel", "auto")(context.Background(), catalogapply.ChangeRequest{
		ManagedRuntime: 1, ProposedRule: "Do not hide errors.", CatalogPolicies: []catalogapply.SourceFile{{Path: "adversaries/operability/rules/actionable-errors/rule.yaml", Content: "guidance: Report hidden errors."}},
	})
	var covered *catalogapply.AlreadyCoveredError
	if err == nil || !errors.As(err, &covered) || covered.CandidateRule != "Do not hide errors." || covered.Adversary != "operability" || covered.RuleID != "actionable-errors" {
		t.Fatalf("err=%v", err)
	}
	if len(provider.requests) != 1 {
		t.Fatalf("model calls=%d want 1", len(provider.requests))
	}
}

func TestCatalogCoverageDoesNotTreatREADMEAsEnforcedRule(t *testing.T) {
	files := []catalogapply.SourceFile{{Path: "adversaries/tenant-and-access-boundaries/README.md", Content: "Authenticated identity wins."}}
	if got := enforcedCatalogRules(files); len(got) != 0 {
		t.Fatalf("README entered enforced rule inventory: %+v", got)
	}
	provider := catalogModelProviderStub{name: "camel", model: "auto", output: json.RawMessage(`{"disposition":"already_covered","adversary":"tenant-and-access-boundaries","rule_id":"base-policy","reason":"The README says so."}`)}
	if err := rejectCoveredCatalogCandidate(context.Background(), provider, catalogapply.ChangeRequest{ProposedRule: "Authenticated session identity wins."}, json.RawMessage(`{"enforced_rules":[]}`), nil); err != nil {
		t.Fatalf("README-only coverage blocked generation: %v", err)
	}
}

func TestCatalogCoverageRequiresRegisteredDeterministicRule(t *testing.T) {
	module := catalogapply.SourceFile{Path: "adversaries/operability/src/rules/actionable-errors.ts", Content: "export function register() {}"}
	if catalogRuleIsEnforced([]catalogapply.SourceFile{module}, "operability", "actionable-errors") {
		t.Fatal("unregistered source module counted as enforced")
	}
	registry := catalogapply.SourceFile{Path: "adversaries/operability/src/deterministic.ts", Content: `import "./rules/actionable-errors.js";`}
	if !catalogRuleIsEnforced([]catalogapply.SourceFile{module, registry}, "operability", "actionable-errors") {
		t.Fatal("registered deterministic rule was not recognized")
	}
	learned := catalogapply.SourceFile{Path: "adversaries/operability/rules/actionable-errors/rule.yaml", Content: "version: 1"}
	if !catalogRuleIsEnforced([]catalogapply.SourceFile{learned}, "operability", "actionable-errors") {
		t.Fatal("loaded learned rule was not recognized")
	}
}

func TestCatalogChangePlannerRejectsMalformedProviderOutputLocally(t *testing.T) {
	for name, overlap := range map[string]json.RawMessage{
		"unknown property": json.RawMessage(`{"disposition":"new_rule","adversary":"","rule_id":"","reason":"distinct","surprise":true}`),
		"invalid enum":     json.RawMessage(`{"disposition":"maybe","adversary":"","rule_id":"","reason":"distinct"}`),
		"missing required": json.RawMessage(`{"disposition":"new_rule","adversary":"","rule_id":""}`),
	} {
		t.Run(name, func(t *testing.T) {
			provider := &catalogSequenceProviderStub{name: "camel", model: "auto", outputs: []json.RawMessage{overlap}}
			runtime := &catalogModelRuntimeStub{provider: provider}
			_, err := catalogChangePlanner(runtime, "camel", "auto")(context.Background(), catalogapply.ChangeRequest{ManagedRuntime: 1})
			if err == nil || !strings.Contains(err.Error(), "decode catalog overlap decision") {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestCatalogChangePlannerRejectsMalformedNestedPlanLocally(t *testing.T) {
	provider := &catalogSequenceProviderStub{name: "camel", model: "auto", outputs: []json.RawMessage{
		json.RawMessage(`{"disposition":"new_rule","adversary":"","rule_id":"","reason":"distinct"}`),
		json.RawMessage(`{"assessments":[{"strategy":"model","confidence":"high","deterministic_value":"none","reason":"semantic judgment only"},{"strategy":"model","confidence":"high","deterministic_value":"none","reason":"no stable repository signal"}]}`),
		json.RawMessage(`{"summary":"Add a concrete operability rule","files":[{"path":"adversaries/operability/rules/a/rule.yaml"},{"path":"adversaries/operability/rules/a/cases.yaml","content":"cases"}]}`),
	}}
	runtime := &catalogModelRuntimeStub{provider: provider}
	_, err := catalogChangePlanner(runtime, "camel", "auto")(context.Background(), catalogapply.ChangeRequest{ManagedRuntime: 1})
	if err == nil || !strings.Contains(err.Error(), "missing property 'content'") {
		t.Fatalf("err=%v", err)
	}
}
