package modelreview

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCloudflareProviderUsesResponsesAPIAndGateway(t *testing.T) {
	var path, authorization, gatewayID string
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		authorization = r.Header.Get("authorization")
		gatewayID = r.Header.Get("cf-aig-gateway-id")
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
		}
		_, _ = w.Write([]byte(`{"status":"completed","output":[{"content":[{"type":"output_text","text":"{\"decision\":\"approve\"}"}]}]}`))
	}))
	defer server.Close()

	values := map[string]string{
		ProviderEnv:            "cloudflare",
		ModelEnv:               "openai/gpt-5.5",
		CloudflareKeyEnv:       "cf-token",
		CloudflareBaseURLEnv:   server.URL,
		CloudflareGatewayIDEnv: "review-gateway",
	}
	provider, err := ProviderFromEnvironment(func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	result, err := provider.Review(context.Background(), validRequest)
	if err != nil {
		t.Fatal(err)
	}
	if provider.Name() != "cloudflare" || provider.Model() != "openai/gpt-5.5" {
		t.Fatalf("provider = %s/%s", provider.Name(), provider.Model())
	}
	if path != "/v1/responses" || authorization != "Bearer cf-token" || gatewayID != "review-gateway" {
		t.Fatalf("request path=%q authorization=%q gateway=%q", path, authorization, gatewayID)
	}
	if payload["model"] != "openai/gpt-5.5" || string(result.Output) != `{"decision":"approve"}` {
		t.Fatalf("payload=%#v result=%s", payload, result.Output)
	}
}

func TestCloudflareProviderBuildsAccountEndpointAndRequiresCredentials(t *testing.T) {
	lookup := func(values map[string]string) LookupEnv {
		return func(key string) (string, bool) {
			value, ok := values[key]
			return value, ok
		}
	}

	provider, err := ProviderFromEnvironment(lookup(map[string]string{
		CloudflareKeyEnv:       "cf-token",
		CloudflareAccountIDEnv: "account-id",
		ModelEnv:               "workers-ai/@cf/openai/gpt-oss-120b",
	}), nil)
	if err != nil {
		t.Fatal(err)
	}
	cloudflare, ok := provider.(*OpenAIProvider)
	if !ok || cloudflare.Name() != "cloudflare" || cloudflare.BaseURL != "https://api.cloudflare.com/client/v4/accounts/account-id/ai" {
		t.Fatalf("provider = %#v", provider)
	}

	for name, values := range map[string]map[string]string{
		"token":   {ProviderEnv: "cloudflare", CloudflareAccountIDEnv: "account-id", ModelEnv: "openai/gpt-5.5"},
		"account": {ProviderEnv: "cloudflare", CloudflareKeyEnv: "cf-token", ModelEnv: "openai/gpt-5.5"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ProviderFromEnvironment(lookup(values), nil)
			if err == nil || !strings.Contains(err.Error(), "required for model provider cloudflare") {
				t.Fatalf("error = %v", err)
			}
		})
	}
}
