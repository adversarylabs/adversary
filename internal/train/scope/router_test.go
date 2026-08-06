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
