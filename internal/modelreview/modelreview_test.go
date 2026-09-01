package modelreview

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var validRequest = Request{
	ProtocolVersion: ProtocolVersion,
	Prompt:          "Review this change as a staff engineer.",
	Input:           json.RawMessage(`{"files":[{"id":"e1","path":"main.go"}]}`),
	Schema:          json.RawMessage(`{"type":"object","additionalProperties":false,"required":["decision"],"properties":{"decision":{"enum":["approve","request_changes"]}}}`),
	Budget:          Budget{MaximumOutputTokens: 2048, TimeoutMS: 5000},
}

type fixtureProvider struct {
	requests []Request
	result   Result
	err      error
}

func (p *fixtureProvider) Name() string  { return "fixture" }
func (p *fixtureProvider) Model() string { return "reviewer-v1" }
func (p *fixtureProvider) Review(_ context.Context, request Request) (Result, error) {
	p.requests = append(p.requests, request)
	return p.result, p.err
}

func TestDecodeRequestIsStrictAndBounded(t *testing.T) {
	data, err := json.Marshal(validRequest)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeRequest(data)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Prompt != validRequest.Prompt || decoded.Budget != validRequest.Budget {
		t.Fatalf("decoded = %#v", decoded)
	}
	for name, input := range map[string]string{
		"unknown field": strings.TrimSuffix(string(data), "}") + `,"secret":"value"}`,
		"trailing json": string(data) + `{}`,
		"bad schema":    strings.Replace(string(data), `"schema":{`, `"schema":"not an object","unused":{`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeRequest([]byte(input)); err == nil {
				t.Fatalf("DecodeRequest accepted %s", input)
			}
		})
	}
}

func TestBrokerAuthenticatesAndValidatesProviderOutput(t *testing.T) {
	provider := &fixtureProvider{result: Result{
		Output: json.RawMessage(`{"decision":"approve"}`),
		Usage:  Usage{InputTokens: 20, OutputTokens: 4},
	}}
	session, err := (Broker{
		Provider: provider,
		Entropy:  bytes.NewReader(bytes.Repeat([]byte{0x42}, 32)),
	}).Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if session.server.IdleTimeout != 31*time.Minute {
		t.Fatalf("broker idle timeout = %s", session.server.IdleTimeout)
	}
	data, _ := json.Marshal(validRequest)

	request, err := http.NewRequest(http.MethodPost, session.Endpoint, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("authorization", "Bearer "+session.Token)
	request.Header.Set("content-type", "application/json")
	request.Header.Set("x-adversary-model-protocol", "1")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.StatusCode, body)
	}
	if !response.Close {
		t.Fatal("model broker response should close the loopback connection")
	}
	var envelope Response
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Provider != "fixture" || envelope.Model != "reviewer-v1" || string(envelope.Output) != `{"decision":"approve"}` {
		t.Fatalf("response = %#v", envelope)
	}
	if len(provider.requests) != 1 {
		t.Fatalf("provider calls = %d", len(provider.requests))
	}

	unauthorized, _ := http.NewRequest(http.MethodPost, session.Endpoint, bytes.NewReader(data))
	unauthorized.Header.Set("authorization", "Bearer wrong")
	unauthorized.Header.Set("x-adversary-model-protocol", "1")
	denied, err := http.DefaultClient.Do(unauthorized)
	if err != nil {
		t.Fatal(err)
	}
	defer denied.Body.Close()
	if denied.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d", denied.StatusCode)
	}
}

func TestBrokerRejectsProviderOutputOutsideRequestedSchema(t *testing.T) {
	provider := &fixtureProvider{result: Result{Output: json.RawMessage(`{"decision":"maybe"}`)}}
	session, err := (Broker{Provider: provider}).Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	data, _ := json.Marshal(validRequest)
	request, _ := http.NewRequest(http.MethodPost, session.Endpoint, bytes.NewReader(data))
	request.Header.Set("authorization", "Bearer "+session.Token)
	request.Header.Set("x-adversary-model-protocol", "1")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d", response.StatusCode)
	}
	var failure ErrorResponse
	if err := json.NewDecoder(response.Body).Decode(&failure); err != nil {
		t.Fatal(err)
	}
	if failure.Error.Code != "invalid_model_output" {
		t.Fatalf("failure = %#v", failure)
	}
}

func TestProviderFromEnvironmentRequiresUnambiguousKeyAndExplicitModel(t *testing.T) {
	lookup := func(values map[string]string) LookupEnv {
		return func(name string) (string, bool) {
			value, ok := values[name]
			return value, ok
		}
	}
	if _, err := ProviderFromEnvironment(lookup(map[string]string{OpenAIKeyEnv: "secret"}), nil); err == nil || !strings.Contains(err.Error(), ModelEnv) {
		t.Fatalf("missing model error = %v", err)
	}
	if _, err := ProviderFromEnvironment(lookup(map[string]string{OpenAIKeyEnv: "one", AnthropicKeyEnv: "two", FireworksKeyEnv: "three", ModelEnv: "reviewer"}), nil); err == nil || !strings.Contains(err.Error(), ProviderEnv) {
		t.Fatalf("ambiguous provider error = %v", err)
	}
	provider, err := ProviderFromEnvironment(lookup(map[string]string{AnthropicKeyEnv: "secret", ModelEnv: "reviewer"}), nil)
	if err != nil {
		t.Fatal(err)
	}
	if provider.Name() != "anthropic" || provider.Model() != "reviewer" {
		t.Fatalf("provider = %s/%s", provider.Name(), provider.Model())
	}
	provider, err = ProviderFromEnvironment(lookup(map[string]string{
		FireworksKeyEnv:               "secret",
		FireworksReasoningEffortEnv:   "none",
		FireworksStructuredRetriesEnv: "2",
		ModelContentDiagnosticsEnv:    "true",
		ModelEnv:                      "accounts/fireworks/models/reviewer",
	}), nil)
	if err != nil {
		t.Fatal(err)
	}
	fireworks, ok := provider.(*FireworksProvider)
	if !ok || fireworks.Model() != "accounts/fireworks/models/reviewer" || fireworks.ReasoningEffort != "none" ||
		fireworks.StructuredOutputRetries != 2 || !fireworks.IncludeContentDiagnostics ||
		fireworks.BaseURL != "https://api.fireworks.ai/inference" {
		t.Fatalf("provider = %#v", provider)
	}
}

func TestProviderFromEnvironmentRejectsInvalidFireworksStructuredRetries(t *testing.T) {
	values := map[string]string{
		FireworksKeyEnv:               "secret",
		FireworksStructuredRetriesEnv: "4",
		ModelEnv:                      "accounts/fireworks/models/reviewer",
	}
	_, err := ProviderFromEnvironment(func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}, nil)
	if err == nil || !strings.Contains(err.Error(), FireworksStructuredRetriesEnv) {
		t.Fatalf("invalid structured retry error = %v", err)
	}
}

func TestProviderFromEnvironmentRejectsInvalidFireworksReasoningEffort(t *testing.T) {
	values := map[string]string{
		FireworksKeyEnv:             "secret",
		FireworksReasoningEffortEnv: "maximum",
		ModelEnv:                    "accounts/fireworks/models/reviewer",
	}
	_, err := ProviderFromEnvironment(func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}, nil)
	if err == nil || !strings.Contains(err.Error(), FireworksReasoningEffortEnv) {
		t.Fatalf("invalid reasoning effort error = %v", err)
	}
}

func TestProviderConfigOverridesEnvironmentSelection(t *testing.T) {
	values := map[string]string{
		ProviderEnv:     "anthropic",
		ModelEnv:        "environment-model",
		AnthropicKeyEnv: "anthropic-secret",
		FireworksKeyEnv: "fireworks-secret",
	}
	lookup := func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}
	provider, err := ProviderFromConfig(Config{Provider: "fireworks"}, lookup, nil)
	if err != nil {
		t.Fatal(err)
	}
	if provider.Name() != "fireworks" || provider.Model() != "environment-model" {
		t.Fatalf("provider = %s/%s", provider.Name(), provider.Model())
	}
	provider, err = ProviderFromConfig(Config{Model: "flag-model"}, lookup, nil)
	if err != nil {
		t.Fatal(err)
	}
	if provider.Name() != "anthropic" || provider.Model() != "flag-model" {
		t.Fatalf("provider = %s/%s", provider.Name(), provider.Model())
	}
}

func TestHTTPClientFromEnvironmentCanDisableKeepAlives(t *testing.T) {
	lookup := func(values map[string]string) LookupEnv {
		return func(name string) (string, bool) {
			value, ok := values[name]
			return value, ok
		}
	}
	client := HTTPClientFromEnvironment(lookup(map[string]string{DisableKeepAlivesEnv: "true"}))
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport = %T", client.Transport)
	}
	if !transport.DisableKeepAlives {
		t.Fatal("DisableKeepAlives = false")
	}

	defaultClient := HTTPClientFromEnvironment(lookup(nil))
	defaultTransport, ok := defaultClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("default transport = %T", defaultClient.Transport)
	}
	if defaultTransport.DisableKeepAlives {
		t.Fatal("default DisableKeepAlives = true")
	}
}

func TestOpenAIProviderUsesResponsesStructuredOutput(t *testing.T) {
	var authorization string
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		authorization = request.Header.Get("authorization")
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(response).Encode(map[string]any{
			"output": []any{map[string]any{"content": []any{map[string]any{
				"type": "output_text",
				"text": `{"decision":"approve"}`,
			}}}},
			"usage": map[string]any{"input_tokens": 10, "output_tokens": 3},
		})
	}))
	defer server.Close()
	provider := &OpenAIProvider{APIKey: "secret", ModelID: "reviewer", BaseURL: server.URL, Client: server.Client()}
	result, err := provider.Review(context.Background(), validRequest)
	if err != nil {
		t.Fatal(err)
	}
	if authorization != "Bearer secret" || string(result.Output) != `{"decision":"approve"}` {
		t.Fatalf("authorization=%q result=%s", authorization, result.Output)
	}
	format := payload["text"].(map[string]any)["format"].(map[string]any)
	if format["type"] != "json_schema" || format["strict"] != true {
		t.Fatalf("format = %#v", format)
	}
}

func TestAnthropicProviderUsesForcedStructuredTool(t *testing.T) {
	var apiKey string
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		apiKey = request.Header.Get("x-api-key")
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(response).Encode(map[string]any{
			"content": []any{map[string]any{
				"type":  "tool_use",
				"name":  "submit_review",
				"input": map[string]any{"decision": "request_changes"},
			}},
			"usage": map[string]any{"input_tokens": 12, "output_tokens": 4},
		})
	}))
	defer server.Close()
	provider := &AnthropicProvider{APIKey: "secret", ModelID: "reviewer", BaseURL: server.URL, Client: server.Client()}
	result, err := provider.Review(context.Background(), validRequest)
	if err != nil {
		t.Fatal(err)
	}
	if apiKey != "secret" || string(result.Output) != `{"decision":"request_changes"}` {
		t.Fatalf("apiKey=%q result=%s", apiKey, result.Output)
	}
	choice := payload["tool_choice"].(map[string]any)
	if choice["name"] != "submit_review" {
		t.Fatalf("tool_choice = %#v", choice)
	}
	tool := payload["tools"].([]any)[0].(map[string]any)
	if tool["strict"] != true {
		t.Fatalf("tool = %#v", tool)
	}
}

func TestFireworksProviderUsesChatCompletionsStructuredOutput(t *testing.T) {
	var authorization, path string
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		authorization = request.Header.Get("authorization")
		path = request.URL.Path
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(response).Encode(map[string]any{
			"choices": []any{map[string]any{"message": map[string]any{
				"content": `{"decision":"approve"}`,
			}}},
			"usage": map[string]any{"prompt_tokens": 14, "completion_tokens": 3},
		})
	}))
	defer server.Close()
	provider := &FireworksProvider{
		APIKey:          "secret",
		ModelID:         "accounts/fireworks/models/reviewer",
		BaseURL:         server.URL,
		Client:          server.Client(),
		ReasoningEffort: "none",
	}
	result, err := provider.Review(context.Background(), validRequest)
	if err != nil {
		t.Fatal(err)
	}
	if authorization != "Bearer secret" || path != "/v1/chat/completions" || string(result.Output) != `{"decision":"approve"}` {
		t.Fatalf("authorization=%q path=%q result=%s", authorization, path, result.Output)
	}
	format := payload["response_format"].(map[string]any)
	jsonSchema := format["json_schema"].(map[string]any)
	if format["type"] != "json_schema" || jsonSchema["name"] != "adversary_model_review" {
		t.Fatalf("response_format = %#v", format)
	}
	if payload["reasoning_effort"] != "none" {
		t.Fatalf("reasoning_effort = %#v", payload["reasoning_effort"])
	}
	messages := payload["messages"].([]any)
	user := messages[1].(map[string]any)["content"].(string)
	if !strings.Contains(user, string(validRequest.Input)) || !strings.Contains(user, string(validRequest.Schema)) {
		t.Fatalf("user content did not include input and schema: %q", user)
	}
	if result.Usage != (Usage{InputTokens: 14, OutputTokens: 3}) {
		t.Fatalf("usage = %#v", result.Usage)
	}
}

func TestFireworksReasoningEffortPreservesSmallStructuredOutputBudgets(t *testing.T) {
	if effort := fireworksReasoningEffort(1_500); effort != "none" {
		t.Fatalf("1,500-token effort = %q", effort)
	}
	if effort := fireworksReasoningEffort(12_000); effort != "low" {
		t.Fatalf("12,000-token effort = %q", effort)
	}
}

func TestFireworksCompatibleStructuredOutputAcceptsOneJSONFence(t *testing.T) {
	output, ok := compatibleStructuredOutput("```json\n{\"decision\":\"approve\"}\n```")
	if !ok || string(output) != `{"decision":"approve"}` {
		t.Fatalf("ok=%v output=%s", ok, output)
	}
	output, ok = compatibleStructuredOutput("Result:\n```json\n{\"decision\":\"approve\"}\n```\nDone.")
	if !ok || string(output) != `{"decision":"approve"}` {
		t.Fatalf("wrapped ok=%v output=%s", ok, output)
	}
	if _, ok := compatibleStructuredOutput("Result unavailable"); ok {
		t.Fatal("content without a JSON object or array must remain invalid")
	}
}

func TestFireworksProviderReportsBoundedMissingOutputDiagnostics(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		_ = json.NewEncoder(response).Encode(map[string]any{
			"choices": []any{map[string]any{
				"finish_reason": "length",
				"message": map[string]any{
					"content":           "",
					"reasoning_content": "internal reasoning",
				},
			}},
		})
	}))
	defer server.Close()
	provider := &FireworksProvider{
		APIKey:  "secret",
		ModelID: "reviewer",
		BaseURL: server.URL,
		Client:  server.Client(),
	}
	_, err := provider.Review(context.Background(), validRequest)
	if err == nil {
		t.Fatal("expected missing output error")
	}
	want := `fireworks response did not contain structured output (choice[0]: finish="length" content_bytes=0 reasoning_bytes=18)`
	if err.Error() != want {
		t.Fatalf("error = %q, want %q", err, want)
	}
}

func TestFireworksProviderRetriesMissingStructuredOutputWithCorrection(t *testing.T) {
	requests := 0
	var lastPayload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests++
		if err := json.NewDecoder(request.Body).Decode(&lastPayload); err != nil {
			t.Fatal(err)
		}
		content := "I should inspect the repository first."
		if requests == 2 {
			content = `{"decision":"approve"}`
		}
		_ = json.NewEncoder(response).Encode(map[string]any{
			"choices": []any{map[string]any{
				"finish_reason": "stop",
				"message":       map[string]any{"content": content},
			}},
			"usage": map[string]any{"prompt_tokens": 10, "completion_tokens": 4},
		})
	}))
	defer server.Close()
	provider := &FireworksProvider{
		APIKey:                  "secret",
		ModelID:                 "reviewer",
		BaseURL:                 server.URL,
		Client:                  server.Client(),
		StructuredOutputRetries: 1,
	}
	result, err := provider.Review(context.Background(), validRequest)
	if err != nil {
		t.Fatal(err)
	}
	if requests != 2 || string(result.Output) != `{"decision":"approve"}` {
		t.Fatalf("requests=%d output=%s", requests, result.Output)
	}
	if result.Usage != (Usage{InputTokens: 20, OutputTokens: 8}) {
		t.Fatalf("usage = %#v", result.Usage)
	}
	messages := lastPayload["messages"].([]any)
	if len(messages) != 3 || !strings.Contains(messages[2].(map[string]any)["content"].(string), "only one JSON value") {
		t.Fatalf("retry messages = %#v", messages)
	}
}

func TestFireworksProviderRetriesStructuredOutputOutsideSchema(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests++
		content := `{"wrong":true}`
		if requests == 2 {
			content = `{"decision":"approve"}`
		}
		_ = json.NewEncoder(response).Encode(map[string]any{
			"choices": []any{map[string]any{
				"finish_reason": "stop",
				"message":       map[string]any{"content": content},
			}},
		})
	}))
	defer server.Close()
	provider := &FireworksProvider{
		APIKey:                  "secret",
		ModelID:                 "reviewer",
		BaseURL:                 server.URL,
		Client:                  server.Client(),
		StructuredOutputRetries: 1,
	}
	result, err := provider.Review(context.Background(), validRequest)
	if err != nil {
		t.Fatal(err)
	}
	if requests != 2 || string(result.Output) != `{"decision":"approve"}` {
		t.Fatalf("requests=%d output=%s", requests, result.Output)
	}
}

func TestFireworksProviderCanIncludeBoundedContentDiagnostic(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		_ = json.NewEncoder(response).Encode(map[string]any{
			"choices": []any{map[string]any{
				"finish_reason": "stop",
				"message":       map[string]any{"content": strings.Repeat("x", 700)},
			}},
		})
	}))
	defer server.Close()
	provider := &FireworksProvider{
		APIKey:                    "secret",
		ModelID:                   "reviewer",
		BaseURL:                   server.URL,
		Client:                    server.Client(),
		IncludeContentDiagnostics: true,
	}
	_, err := provider.Review(context.Background(), validRequest)
	if err == nil || !strings.Contains(err.Error(), `content_preview="`) || len(err.Error()) > 700 {
		t.Fatalf("bounded diagnostic = %q", err)
	}
}
