package adversarylabs

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestRecordUsagePostsAggregateOutcomes(t *testing.T) {
	var payload map[string]any
	client := Client{
		BaseURL: "https://api.test",
		HTTP: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path != "/v1/cli/usage" {
				t.Fatalf("path = %q", req.URL.Path)
			}
			if got := req.Header.Get("Authorization"); got != "Bearer token" {
				t.Fatalf("authorization = %q", got)
			}
			if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{}`)),
				Header:     make(http.Header),
			}, nil
		})},
	}

	err := client.RecordUsage(context.Background(), "token", "run", "2026.8.26", RunUsageReport{
		Adversaries: []string{"go/security"},
		DurationMS:  1234,
		GitRef:      "feature/run-targets",
		GitSHA:      strings.Repeat("a", 40),
		PullRequest: 213,
		Results: []RunUsageAdversaryResult{{
			Adversary: "go/security",
			Status:    "findings",
			HighCount: 2,
		}},
		Phases: []RunUsagePhase{{Name: "execute-reviews", Status: "completed", StartedAtUnixNano: "1", EndedAtUnixNano: "2"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if payload["duration_ms"] != float64(1234) {
		t.Fatalf("payload = %#v", payload)
	}
	if payload["git_ref"] != "feature/run-targets" || payload["git_sha"] != strings.Repeat("a", 40) || payload["pull_request"] != float64(213) {
		t.Fatalf("source context = %#v", payload)
	}
	if phases, ok := payload["phases"].([]any); !ok || len(phases) != 1 {
		t.Fatalf("phases = %#v", payload["phases"])
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"finding_title", "repository", "file", "path"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("payload contains %q: %s", forbidden, encoded)
		}
	}
}

func TestPullTelemetryReturnsOTLPJSON(t *testing.T) {
	client := Client{
		BaseURL: "https://api.test",
		HTTP: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path != "/v1/cli/telemetry/0123456789abcdef0123456789abcdef" {
				t.Fatalf("path = %q", req.URL.Path)
			}
			if got := req.Header.Get("Authorization"); got != "Bearer token" {
				t.Fatalf("authorization = %q", got)
			}
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"resourceSpans":[]}`)), Header: make(http.Header)}, nil
		})},
	}
	raw, err := client.PullTelemetry(context.Background(), "token", "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"resourceSpans":[]}` {
		t.Fatalf("raw = %s", raw)
	}
}

func TestRecordUsageLifecycleUsesDedicatedEndpoint(t *testing.T) {
	client := Client{BaseURL: "https://api.test", HTTP: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/v1/cli/runs" {
			t.Fatalf("path = %q", req.URL.Path)
		}
		var payload map[string]any
		if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if payload["action"] != "finish" || payload["outcome"] != "canceled" || payload["trace_id"] != "0123456789abcdef0123456789abcdef" {
			t.Fatalf("payload: %#v", payload)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
	})}}
	if err := client.RecordUsage(context.Background(), "token", "run", "dev", RunUsageReport{Action: "finish", Outcome: "canceled", TraceID: "0123456789abcdef0123456789abcdef", Adversaries: []string{"local"}}); err != nil {
		t.Fatal(err)
	}
}
