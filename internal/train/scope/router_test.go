package scope

import "testing"

func TestRouterConcurrencyVsEngReview(t *testing.T) {
	r := &Router{
		Candidates: []Candidate{
			{ID: "engineering-review", AdversaryName: "engineering-review", Mission: "staff eng judgment"},
			{ID: "go-concurrency", AdversaryName: "go-concurrency", Mission: "Go concurrency races lifecycle"},
			{ID: "githubactions", AdversaryName: "githubactions", Mission: "GitHub Actions workflows"},
		},
	}
	body := "This does not test the exporter-serialization guarantee. overlapping Export, ForceFlush, and Shutdown with mutex"
	route := r.RouteComment(body, "sdk/log/batch_test.go", "MrAlias")
	if route.OwnerID != "go-concurrency" {
		t.Fatalf("owner=%s reason=%s", route.OwnerID, route.Reason)
	}
}

func TestRouterGHA(t *testing.T) {
	r := &Router{
		Candidates: []Candidate{
			{ID: "engineering-review", AdversaryName: "engineering-review", Mission: "staff eng"},
			{ID: "githubactions", AdversaryName: "githubactions", Mission: "GHA", FileGlobs: []string{".github/workflows/*.yml"}},
		},
	}
	body := "Using --privileged gives the job container broad access on a self-hosted runner"
	route := r.RouteComment(body, ".github/workflows/benchmark.yml", "alice")
	if route.OwnerID != "githubactions" {
		t.Fatalf("owner=%s reason=%s", route.OwnerID, route.Reason)
	}
}

func TestRouterDoesNotOwnSoftOKOrNit(t *testing.T) {
	r := &Router{
		Candidates: []Candidate{
			{ID: "engineering-review", AdversaryName: "engineering-review", Mission: "staff eng judgment"},
			{ID: "go-concurrency", AdversaryName: "go-concurrency", Mission: "Go concurrency races lifecycle"},
			{ID: "go", AdversaryName: "go", Mission: "Go TLS shell filesystem"},
		},
		UseLLM: false,
	}
	cases := []struct {
		name, body, path string
	}{
		{"lgtm", "I'm more satisfied with this change. A nit on package comment, but nothing blocking. LGTM", ""},
		{"soft-ok", "Among all changes this is the only condition that gets added for trace. But i think its ok as there are no spec-level difference.", "internal/shared/attrnorm/truncate.go.tmpl"},
		{"package-nit", "Nit; more description on package\n```go\n// Package attrnorm normalizes attribute values by:\n```", "internal/shared/attrnorm/dedup.go.tmpl"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			route := r.RouteComment(tc.body, tc.path, "ps-mir")
			if route.OwnerID != "" || route.Decision != OutOfScope {
				t.Fatalf("owner=%q decision=%s reason=%s — expected none/out_of_scope", route.OwnerID, route.Decision, route.Reason)
			}
		})
	}
}

func TestRouterDocsPathNotKustomize(t *testing.T) {
	r := &Router{
		Candidates: []Candidate{
			{ID: "engineering-review", AdversaryName: "engineering-review", Mission: "staff eng"},
			{ID: "kustomize", AdversaryName: "kustomize", Mission: "mutable images secrets dangerous patches"},
		},
		UseLLM: false,
	}
	route := r.RouteComment(
		"s/Providers/Generators/ everywhere.\n\nI think this horse left the barn.",
		"docs/book/pages/reference/kustomize.md",
		"monopole",
	)
	if route.OwnerID != "" || route.Decision != OutOfScope {
		t.Fatalf("docs sed-nit must not route to kustomize: owner=%q dec=%s reason=%s", route.OwnerID, route.Decision, route.Reason)
	}
	route2 := r.RouteComment(
		"Teach kustomize about your custom resources by providing a CRD.",
		"docs/book/pages/reference/kustomize.md",
		"monopole",
	)
	if route2.OwnerID != "" {
		t.Fatalf("docs reference text must not be owned: %+v", route2)
	}
}

func TestRouterTraceIsNotConcurrency(t *testing.T) {
	// Regression: substring "race" inside "trace" must not boost go-concurrency.
	r := &Router{
		Candidates: []Candidate{
			{ID: "engineering-review", AdversaryName: "engineering-review", Mission: "staff eng"},
			{ID: "go-concurrency", AdversaryName: "go-concurrency", Mission: "races"},
		},
		UseLLM: false,
	}
	// Soft OK about "trace" must stay unowned (not concurrency).
	route := r.RouteComment(
		"This is the only condition that gets added for trace. But i think its ok.",
		"attrnorm/truncate.go",
		"alice",
	)
	if route.OwnerID == "go-concurrency" {
		t.Fatalf("trace soft-OK must not route to go-concurrency: %+v", route)
	}
}

func TestRouterBotNone(t *testing.T) {
	r := &Router{Candidates: []Candidate{{ID: "engineering-review", AdversaryName: "engineering-review", Mission: "x"}}}
	route := r.RouteComment("## Pull request overview\nThis PR does stuff", "", "copilot[bot]")
	if route.OwnerID != "" {
		t.Fatalf("expected none, got %s", route.OwnerID)
	}
}

func TestRouterConcurrentAPITestGapBeatsGoTesting(t *testing.T) {
	r := &Router{
		Candidates: []Candidate{
			{ID: "engineering-review", AdversaryName: "engineering-review", Mission: "staff eng"},
			{ID: "go-testing", AdversaryName: "go-testing", Mission: "Go testing harness"},
			{ID: "go-concurrency", AdversaryName: "go-concurrency", Mission: "Go concurrency races lifecycle concurrent API"},
		},
		UseLLM: false,
	}
	body := "This does not test the exporter-serialization guarantee introduced by this PR. `testExporter` protects its state with atomics and a mutex, so overlapping `Export`, `ForceFlush`, and `Shutdown` calls remain race-free, and there is no assertion that would fail if the worker invoked them concurrently. Please instrument the exporter with a shared active-call or max-active counter across all three methods, or coordinate blocking callbacks, and assert that the maximum is one while `OnEmit`, `ForceFlush`, and `Shutdown` race."
	route := r.RouteComment(body, "sdk/log/batch_test.go", "MrAlias")
	if route.OwnerID != "go-concurrency" {
		t.Fatalf("concurrent API test gap must own go-concurrency, got owner=%s reason=%s", route.OwnerID, route.Reason)
	}
}

func TestRouterCommitMessageWordingNone(t *testing.T) {
	r := &Router{
		Candidates: []Candidate{
			{ID: "go-concurrency", AdversaryName: "go-concurrency", Mission: "races"},
			{ID: "engineering-review", AdversaryName: "engineering-review", Mission: "staff"},
		},
		UseLLM: false,
	}
	body := "Can you please change\n> If a policy store expired (e.g. Windows Group Policy churn closing an Expirable store's Done channel)\n\nto\n> If a policy store is closed\n\nor similar in the commit message? The example provided is incorrect and misleading."
	route := r.RouteComment(body, "", "nickkhyl")
	if route.OwnerID != "" {
		t.Fatalf("commit message wording must not be gold: %+v", route)
	}
}

func TestRouterRejectsSpecialistOutsideDeclaredFileSurface(t *testing.T) {
	r := &Router{
		Candidates: []Candidate{
			{ID: "engineering-review", AdversaryName: "engineering-review", Mission: "staff eng", Languages: []string{"any"}},
			{ID: "go-testing", AdversaryName: "go-testing", Mission: "Go tests only; non-Go is out of scope", Languages: []string{"go"}, FileGlobs: []string{"**/*_test.go"}},
			{ID: "typescript", AdversaryName: "typescript", Mission: "TypeScript and JavaScript only", Languages: []string{"typescript"}, FileGlobs: []string{"**/*.ts", "**/*.tsx"}},
		},
	}

	java := r.RouteComment(
		"This regression test is incomplete: please assert the invalid enum returns the expected error.",
		"app/src/test/java/example/DataContractsResourceTest.java",
		"alice",
	)
	if java.OwnerID == "go-testing" {
		t.Fatalf("Java test must not route to go-testing: %+v", java)
	}

	python := r.RouteComment(
		"This validation is incomplete and allows an incorrect runtime schema.",
		"airflow/provider_manager.py",
		"bob",
	)
	if python.OwnerID == "typescript" {
		t.Fatalf("Python must not route to typescript: %+v", python)
	}
}

func TestRouterNitsFailsClosedWithoutLLM(t *testing.T) {
	r := &Router{
		Candidates: []Candidate{
			{ID: "engineering-review", AdversaryName: "engineering-review", Mission: "staff eng", Languages: []string{"any"}},
			{ID: "nits", AdversaryName: "nits", Mission: "non-blocking maintainer taste", Languages: []string{"any"}, FileGlobs: []string{"**/*"}},
		},
	}

	nit := r.RouteComment("Nit: rename this variable for consistency with the sibling helper.", "src/cache.java", "alice")
	if nit.OwnerID == "nits" {
		t.Fatalf("keyword-only taste feedback must not route to nits: %+v", nit)
	}

	redundant := r.RouteComment("Non-blocking: this masking is already applied by the downstream recorder, so this call is redundant noise.", "src/log.go", "alice")
	if redundant.OwnerID == "nits" {
		t.Fatalf("keyword-only cleanup must not route to nits: %+v", redundant)
	}

	crash := r.RouteComment("This unguarded validation can crash startup when third-party metadata is malformed; please preserve error handling.", "provider_manager.py", "bob")
	if crash.OwnerID == "nits" {
		t.Fatalf("runtime correctness concern must not route to nits: %+v", crash)
	}
}

func TestRouterBroadGeneralistKeepsNits(t *testing.T) {
	r := &Router{
		Candidates: []Candidate{
			{
				ID:            "torvalds",
				AdversaryName: "torvalds",
				Mission:       "Everything is in scope. Do not exclude nits. Clarity, style, and nits (**all in scope**).",
			},
		},
	}
	route := r.RouteComment("nit: rename this variable for clarity", "core/qt-ble.cpp", "torvalds")
	if route.Decision != InScope || route.OwnerID != "torvalds" {
		t.Fatalf("got owner=%q decision=%s reason=%s", route.OwnerID, route.Decision, route.Reason)
	}
	// Technical discussion without eng-review "bug/race" keywords must still land.
	route = r.RouteComment(
		"Yeah, a lambda expression is certainly conceptually the right thing. Why not use QList::clear()?",
		"core/qt-ble.cpp",
		"torvalds",
	)
	if route.Decision != InScope || route.OwnerID != "torvalds" {
		t.Fatalf("got owner=%q decision=%s reason=%s", route.OwnerID, route.Decision, route.Reason)
	}
}

func TestRouterRejectsConversationArtifactsBeforeBroadRouting(t *testing.T) {
	r := &Router{
		Candidates: []Candidate{
			{ID: "engineering-review", AdversaryName: "engineering-review", Mission: "staff engineering contracts and validation"},
			{ID: "nits", AdversaryName: "nits", Mission: "non-blocking maintainer taste"},
			{ID: "person-maintainer", AdversaryName: "person-maintainer", Mission: "Everything is in scope. Do not exclude nits."},
		},
		UseLLM: false,
	}

	falseGold := []string{
		"Fixed in 5fbd91a. Invalid column entries now fall back to form_data and regression coverage was added.",
		"Updated",
		"Overall, this is a correct behavior-preserving cleanup that removes redundant branching.",
		"We don't need to worry about backwards compatibility here because this API has not shipped.",
	}
	for _, body := range falseGold {
		route := r.RouteComment(body, "src/query.py", "author")
		if route.OwnerID != "" || route.Decision != OutOfScope {
			t.Errorf("conversation artifact became gold: %q => %+v", body, route)
		}
	}

	requests := []string{
		"Please reject invalid column entries instead of silently discarding the validation error.",
		"LGTM overall, but please reject invalid column entries instead of silently discarding the validation error.",
		"Could you use the class token instead of passing a duplicate value through every helper?",
		"Nit: align this name with the sibling helper so the two call sites read consistently.",
	}
	for _, body := range requests {
		route := r.RouteComment(body, "src/query.py", "reviewer")
		if route.OwnerID == "" || route.Decision != InScope {
			t.Errorf("real reviewer request was rejected: %q => %+v", body, route)
		}
	}
}

func TestRouteLLMDecisionRequiresGoldQualityGates(t *testing.T) {
	candidates := []Candidate{{ID: "engineering-review"}, {ID: "go-concurrency"}}
	base := routeDecision{
		OwnerID: "engineering-review", Material: true, Actionable: true,
		ChangeLocal: true, EngineeringPrimary: true,
	}
	if got := routeFromLLMDecision(base, candidates); got.OwnerID != "engineering-review" || got.Decision != InScope {
		t.Fatalf("valid engineering route rejected: %+v", got)
	}

	for name, mutate := range map[string]func(*routeDecision){
		"immaterial":         func(d *routeDecision) { d.Material = false },
		"not-actionable":     func(d *routeDecision) { d.Actionable = false },
		"pre-existing":       func(d *routeDecision) { d.ChangeLocal = false },
		"specialist-primary": func(d *routeDecision) { d.EngineeringPrimary = false },
	} {
		t.Run(name, func(t *testing.T) {
			decision := base
			mutate(&decision)
			got := routeFromLLMDecision(decision, candidates)
			if got.OwnerID != "" || got.Decision != OutOfScope {
				t.Fatalf("gate accepted %+v", got)
			}
		})
	}
}

func TestCandidatePathEligibleTreatsAnyAndUnsetAsLanguageNeutral(t *testing.T) {
	for _, candidate := range []Candidate{
		{ID: "legacy"},
		{ID: "engineering-review", Languages: []string{"any"}},
	} {
		if ok, reason := candidatePathEligible("src/example.java", candidate); !ok {
			t.Fatalf("%s should be language-neutral: %s", candidate.ID, reason)
		}
	}
	if ok, _ := candidatePathEligible("src/example.java", Candidate{
		ID: "complexity", Languages: []string{"any"}, FileGlobs: []string{"**/*.ts", "**/*.js"},
	}); ok {
		t.Fatal("an inferred 'any' must not bypass declared file globs")
	}
	if ok, _ := candidatePathEligible("src/example.java", Candidate{
		ID: "go-testing", Languages: []string{"go"}, FileGlobs: []string{"**/*_test.go"},
	}); ok {
		t.Fatal("go-testing must reject a Java path")
	}
	if ok, _ := candidatePathEligible("", Candidate{
		ID: "go-testing", Languages: []string{"go"}, FileGlobs: []string{"**/*_test.go"},
	}); ok {
		t.Fatal("language-specific package must fail closed without file evidence")
	}
	if ok, _ := candidatePathEligible("", Candidate{
		ID: "complexity", Languages: []string{"any"}, FileGlobs: []string{"**/*.ts", "**/*.js"},
	}); ok {
		t.Fatal("pathless comment must not bypass restrictive file globs")
	}
	if ok, reason := candidatePathEligible("", Candidate{
		ID: "nits", Languages: []string{"any"}, FileGlobs: []string{"**/*"},
	}); !ok {
		t.Fatalf("universal file surface should accept a pathless comment: %s", reason)
	}
}

func TestRouteFromLLMDecisionRejectsOwnerOutsideDeclaredFileSurface(t *testing.T) {
	candidates := []Candidate{
		{ID: "typescript", Languages: []string{"typescript"}, FileGlobs: []string{"**/*.ts", "**/*.tsx"}},
		{ID: "engineering-review", Languages: []string{"any"}},
	}
	decision := routeDecision{
		OwnerID: "typescript", Reason: "schema strictness", Material: true,
		Actionable: true, ChangeLocal: true,
	}
	got := routeFromLLMDecisionForPath(decision, candidates, "airflow/provider.yaml.schema.json")
	if got.OwnerID != "" || got.Decision != OutOfScope {
		t.Fatalf("LLM-selected TypeScript owner must be rejected for JSON schema: %+v", got)
	}
}

func TestRouteFromLLMDecisionEnforcesNitsSemanticGate(t *testing.T) {
	candidates := []Candidate{{ID: "nits", Languages: []string{"any"}, FileGlobs: []string{"**/*"}}}
	decision := routeDecision{
		OwnerID: "nits", Reason: "startup behavior", Material: true,
		Actionable: true, ChangeLocal: true,
	}
	got := routeFromLLMDecisionForPath(
		decision,
		candidates,
		"provider_manager.py",
	)
	if got.OwnerID != "" || got.Decision != OutOfScope {
		t.Fatalf("LLM-selected nits owner must reject correctness concerns: %+v", got)
	}

	got = routeFromLLMDecisionForPath(
		func() routeDecision {
			decision.NonBlocking = true
			return decision
		}(),
		candidates,
		"src/log.go",
	)
	if got.OwnerID != "nits" || got.Decision != InScope {
		t.Fatalf("LLM-selected nits owner should keep non-blocking cleanup: %+v", got)
	}
}

func TestNitsHeuristicAlwaysFailsClosed(t *testing.T) {
	cases := []string{
		"This redundant branch is broken and returns incorrect behavior.",
		"Cleanup is needed because this duplicate write causes a failure.",
		"This unused guard leaves an unhandled exception during startup.",
		"This duplicate write charges the customer twice.",
		"TODO: the refund is never issued when capture fails.",
		"Nit: this duplicate write charges the customer twice.",
	}
	for _, body := range cases {
		got := classifyNitsCandidate(body, "src/service.go")
		if got.Decision != OutOfScope {
			t.Fatalf("material defect routed to nits: %q => %+v", body, got)
		}
	}
}
