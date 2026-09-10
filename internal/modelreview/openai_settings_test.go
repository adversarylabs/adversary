package modelreview

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOpenAIRequestSettings(t *testing.T) {
	for _, tc := range []struct {
		name, model, effort       string
		requested, override, want int
		wantEffort                string
	}{
		{"planning", "gpt-5.6-luna", "", 1500, 0, 16384, "high"},
		{"review", "gpt-5.6-luna", "", 8000, 0, 32000, "high"},
		{"verification", "gpt-5.6-luna", "", 12000, 0, 48000, "high"},
		{"large", "gpt-5.6-luna", "", 16000, 0, 64000, "high"},
		{"ceiling", "gpt-5.6-luna", "", 65536, 0, 65536, "high"},
		{"no reasoning", "gpt-5.6-luna", "none", 1500, 0, 1500, "none"},
		{"explicit cap", "gpt-5.6-luna", "low", 8000, 2000, 2000, "low"},
		{"explicit cap without reasoning", "gpt-5.6-luna", "none", 1500, 2000, 2000, "none"},
		{"other model", "other", "", 1500, 0, 1500, ""},
		{"not a prefix match", "gpt-5.6-luna-custom", "", 1500, 0, 1500, ""},
		{"other explicit", "other", "high", 1500, 4096, 4096, "high"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := OpenAIProvider{ModelID: tc.model, ReasoningEffort: tc.effort, MaxOutputTokens: tc.override}
			effort, tokens := p.requestSettings(tc.requested)
			if effort != tc.wantEffort || tokens != tc.want {
				t.Fatalf("got %s/%d; want %s/%d", effort, tokens, tc.wantEffort, tc.want)
			}
		})
	}
}

func TestOpenAISettingsReachResponsesAPI(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(map[bool]string{false: "defaults", true: "overrides"}[explicit], func(t *testing.T) {
			var payload map[string]any
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/responses" {
					t.Errorf("path=%s", r.URL.Path)
				}
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Error(err)
				}
				_, _ = w.Write([]byte(`{"status":"completed","output":[{"content":[{"type":"output_text","text":"{\"decision\":\"approve\"}"}]}]}`))
			}))
			defer server.Close()
			values := map[string]string{ProviderEnv: "openai", ModelEnv: "gpt-5.6-luna", OpenAIKeyEnv: "test", OpenAIBaseURLEnv: server.URL}
			wantEffort, wantCap := "high", float64(16384)
			if explicit {
				values[OpenAIReasoningEffortEnv] = "low"
				values[OpenAIMaxOutputTokensEnv] = "2048"
				wantEffort = "low"
				wantCap = 2048
			}
			provider, err := ProviderFromEnvironment(func(k string) (string, bool) { v, ok := values[k]; return v, ok }, server.Client())
			if err != nil {
				t.Fatal(err)
			}
			req := validRequest
			req.Budget.MaximumOutputTokens = 1500
			if _, err := provider.Review(context.Background(), req); err != nil {
				t.Fatal(err)
			}
			if payload["max_output_tokens"] != wantCap || payload["reasoning"].(map[string]any)["effort"] != wantEffort || payload["store"] != false {
				t.Fatalf("unexpected settings: %#v", payload)
			}
		})
	}
}

func TestOpenAIRejectsInvalidSettings(t *testing.T) {
	for _, tc := range []struct{ key, value string }{{OpenAIMaxOutputTokensEnv, "0"}, {OpenAIMaxOutputTokensEnv, "-1"}, {OpenAIMaxOutputTokensEnv, "65537"}, {OpenAIMaxOutputTokensEnv, "invalid"}, {OpenAIReasoningEffortEnv, "unlimited"}} {
		t.Run(tc.key+tc.value, func(t *testing.T) {
			values := map[string]string{ProviderEnv: "openai", ModelEnv: "gpt-5.6-luna", OpenAIKeyEnv: "test", tc.key: tc.value}
			_, err := ProviderFromEnvironment(func(k string) (string, bool) { v, ok := values[k]; return v, ok }, nil)
			if err == nil || !strings.Contains(err.Error(), tc.key) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestOpenAIIncompleteResponseNeverBecomesSuccessfulReview(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		// Even parseable partial JSON must not be accepted when the API says incomplete.
		_, _ = w.Write([]byte(`{"status":"incomplete","incomplete_details":{"reason":"max_output_tokens"},"output":[{"content":[{"type":"output_text","text":"{\"decision\":\"approve\"}"}]}]}`))
	}))
	defer server.Close()
	p := OpenAIProvider{ModelID: "gpt-5.6-luna", BaseURL: server.URL, Client: server.Client(), MaxOutputTokens: 2048}
	result, err := p.Review(context.Background(), validRequest)
	var providerErr *ProviderError
	if !errors.As(err, &providerErr) || providerErr.Code != "openai_output_token_limit" || !strings.Contains(err.Error(), "max_output_tokens=2048") {
		t.Fatalf("error=%v", err)
	}
	if len(result.Output) != 0 || calls != 1 || providerErr.Retryable {
		t.Fatalf("unexpected success/retry: output=%s calls=%d error=%+v", result.Output, calls, providerErr)
	}
}
