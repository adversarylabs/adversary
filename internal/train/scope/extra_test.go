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
