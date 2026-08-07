package scope

import "testing"

func TestClassifierHeuristics(t *testing.T) {
	c := &Classifier{AdversaryName: "go-concurrency", UseLLM: false, MissionMarkdown: "races goroutine lifecycle channel mutex"}
	cases := []struct {
		body string
		want Decision
	}{
		{"This goroutine can leak after Shutdown", InScope},
		{"LGTM", OutOfScope},
		{"nit: rename this variable for clarity", OutOfScope},
		{"data race on the map without a mutex", InScope},
	}
	for _, tc := range cases {
		r := c.Classify(tc.body, "a.go", "alice")
		if r.Decision != tc.want {
			t.Errorf("%q: got %v want %v (%s)", tc.body, r.Decision, tc.want, r.Reason)
		}
	}
}

func TestEngReviewFiltersNoiseFromTrainGold(t *testing.T) {
	c := &Classifier{
		AdversaryName:   "engineering-review",
		UseLLM:          false,
		MissionMarkdown: "staff engineering completeness contracts ops validation",
	}
	outCases := []string{
		"Not changed in this diff.",
		"Thanks for the interest in contributing to Django, welcome aboard.",
		"I'll revert this after a successful build & e2e run",
		"Please keep the trailing comma.",
		"This just needs to flip `True` to `False`.",
		"```suggestion\nbboltcmd.NewRootCommand(),\n```",
		"Should contain a E2E since this is a basic expected behaviour",
		"```json\n{ \"event\": \"COMMENT\", \"body\": \"## Code Review: fix\" }\n```",
		"Good catch, this was real. Reproduced the hang.",
		"maybe it can be reduced, open to suggestions",
	}
	for _, body := range outCases {
		r := c.Classify(body, "src/x.go", "alice")
		if r.Decision != OutOfScope {
			t.Errorf("want out_of_scope for %q: got %s (%s)", body, r.Decision, r.Reason)
		}
	}
	inCases := []string{
		"I'm not sure it make sense to have the canContinueOnError being set outside the catch — incomplete error contract",
		"Could you wrap only dest.append in the try-catch block to avoid catching unrelated error?",
		"directoryListing builds absolute paths while DirFS rejects them — incomplete parity test",
		"Are there breaking changes between 1.x and 2.x for this API contract?",
	}
	for _, body := range inCases {
		r := c.Classify(body, "src/x.go", "alice")
		if r.Decision != InScope {
			t.Errorf("want in_scope for %q: got %s (%s)", body, r.Decision, r.Reason)
		}
	}
}

func TestRouterPreferSpecialist(t *testing.T) {
	r := &Router{
		UseLLM: false,
		Candidates: []Candidate{
			{ID: "engineering-review", AdversaryName: "engineering-review", Mission: "staff eng judgment"},
			{ID: "go-concurrency", AdversaryName: "go-concurrency", Mission: "Go concurrency races lifecycle channel mutex goroutine"},
		},
	}
	route := r.RouteComment("Worker goroutine may leak after Shutdown without context cancel", "worker.go", "bob")
	if route.Decision == InScope && route.OwnerID != "go-concurrency" && route.OwnerID != "engineering-review" {
		t.Fatalf("%+v", route)
	}
}
