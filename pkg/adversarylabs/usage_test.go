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
		Results: []RunUsageAdversaryResult{{
			Adversary: "go/security",
			Status:    "findings",
			HighCount: 2,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if payload["duration_ms"] != float64(1234) {
		t.Fatalf("payload = %#v", payload)
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
