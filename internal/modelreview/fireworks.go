package modelreview

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type FireworksProvider struct {
	APIKey                    string
	ModelID                   string
	BaseURL                   string
	Client                    *http.Client
	ReasoningEffort           string
	ResponseFormat            string
	StructuredOutputRetries   int
	RequestRetries            int
	IncludeContentDiagnostics bool
}

// CamelProvider talks to camelStream's OpenAI-compatible Chat Completions
// endpoint using Camel's own credential and configuration namespace.
type CamelProvider struct {
	APIKey                    string
	ModelID                   string
	BaseURL                   string
	Client                    *http.Client
	ReasoningEffort           string
	ResponseFormat            string
	StructuredOutputRetries   int
	RequestRetries            int
	IncludeContentDiagnostics bool
}

type chatCompletionsResponse struct {
	Choices []chatCompletionsChoice `json:"choices"`
	Usage   struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}

type chatCompletionsChoice struct {
	Message struct {
		Content          string `json:"content"`
		ReasoningContent string `json:"reasoning_content"`
	} `json:"message"`
	FinishReason string `json:"finish_reason"`
}

func (p *FireworksProvider) Name() string  { return "fireworks" }
func (p *FireworksProvider) Model() string { return p.ModelID }

func (p *FireworksProvider) Review(ctx context.Context, request Request) (Result, error) {
	return reviewChatCompletions(ctx, p.Name(), p.APIKey, p.ModelID, p.BaseURL, p.Client, p.ReasoningEffort, p.ResponseFormat, p.StructuredOutputRetries, p.RequestRetries, p.IncludeContentDiagnostics, request)
}

func (p *CamelProvider) Name() string  { return "camel" }
func (p *CamelProvider) Model() string { return p.ModelID }

func (p *CamelProvider) Review(ctx context.Context, request Request) (Result, error) {
	return reviewChatCompletions(ctx, p.Name(), p.APIKey, p.ModelID, p.BaseURL, p.Client, p.ReasoningEffort, p.ResponseFormat, p.StructuredOutputRetries, p.RequestRetries, p.IncludeContentDiagnostics, request)
}

func reviewChatCompletions(ctx context.Context, providerName, apiKey, modelID, baseURL string, client *http.Client, reasoningEffort, responseFormat string, structuredOutputRetries, requestRetries int, includeContentDiagnostics bool, request Request) (Result, error) {
	var schema any
	if err := json.Unmarshal(request.Schema, &schema); err != nil {
		return Result{}, fmt.Errorf("decode model schema: %w", err)
	}
	messages := []map[string]any{
		{"role": "system", "content": request.Prompt},
		{"role": "user", "content": chatCompletionsReviewInput(request)},
	}
	var lastResponse chatCompletionsResponse
	var lastSchemaError error
	usage := Usage{}
	for attempt := 0; attempt <= structuredOutputRetries; attempt++ {
		attemptMessages := messages
		if attempt > 0 {
			attemptMessages = append(append([]map[string]any{}, messages...), map[string]any{
				"role":    "user",
				"content": "The previous response did not contain valid structured output. Return only one JSON value matching the supplied schema, with no prose or markdown.",
			})
		}
		payload := map[string]any{
			"model":            modelID,
			"max_tokens":       request.Budget.MaximumOutputTokens,
			"reasoning_effort": chatCompletionsReasoningEffort(reasoningEffort, request.Budget.MaximumOutputTokens),
			"messages":         attemptMessages,
			"response_format":  chatCompletionsResponseFormat(responseFormat, schema),
		}
		var data []byte
		var status int
		var responseHeaders http.Header
		var err error
		for requestAttempt := 0; ; requestAttempt++ {
			data, status, responseHeaders, err = postJSONWithHeaders(ctx, client, baseURL+"/v1/chat/completions", map[string]string{
				"authorization": "Bearer " + apiKey,
			}, payload)
			retryable := err != nil || status == http.StatusTooManyRequests || status >= 500
			if !retryable || requestAttempt >= requestRetries || ctx.Err() != nil {
				break
			}
			if err := waitForProviderRetry(ctx, providerRetryDelay(requestAttempt, responseHeaders)); err != nil {
				return Result{}, err
			}
		}
		if err != nil {
			return Result{}, err
		}
		if status < 200 || status >= 300 {
			return Result{}, providerHTTPError(providerName, status, data)
		}
		var response chatCompletionsResponse
		if err := json.Unmarshal(data, &response); err != nil {
			return Result{}, fmt.Errorf("decode %s response: %w", providerName, err)
		}
		usage.InputTokens += response.Usage.PromptTokens
		usage.OutputTokens += response.Usage.CompletionTokens
		lastSchemaError = nil
		for _, choice := range response.Choices {
			if output, ok := compatibleStructuredOutput(choice.Message.Content); ok {
				if err := ValidateOutput(request.Schema, output); err == nil {
					return Result{Output: output, Usage: usage}, nil
				} else {
					lastSchemaError = err
				}
			}
		}
		lastResponse = response
	}
	code := providerName + "_missing_output"
	message := chatCompletionsMissingOutputMessage(providerName, lastResponse.Choices, includeContentDiagnostics)
	if lastSchemaError != nil {
		code = providerName + "_invalid_output"
		message = fmt.Sprintf("%s structured output failed schema validation after retries: %v", providerName, lastSchemaError)
	}
	return Result{}, &ProviderError{
		Code:    code,
		Message: message,
	}
}

func providerRetryDelay(attempt int, headers http.Header) time.Duration {
	if headers != nil {
		if seconds, err := strconv.Atoi(strings.TrimSpace(headers.Get("Retry-After"))); err == nil && seconds >= 0 {
			delay := time.Duration(seconds) * time.Second
			if delay > 30*time.Second {
				return 30 * time.Second
			}
			return delay
		}
	}
	delay := 250 * time.Millisecond * time.Duration(1<<min(attempt, 6))
	if delay > 10*time.Second {
		return 10 * time.Second
	}
	return delay
}

func waitForProviderRetry(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func chatCompletionsResponseFormat(responseFormat string, schema any) map[string]any {
	if responseFormat == "json_object" {
		return map[string]any{"type": "json_object"}
	}
	return map[string]any{
		"type": "json_schema",
		"json_schema": map[string]any{
			"name":   "adversary_model_review",
			"schema": schema,
		},
	}
}

func chatCompletionsReasoningEffort(reasoningEffort string, maximumOutputTokens int) string {
	if reasoningEffort != "" {
		return reasoningEffort
	}
	return defaultChatCompletionsReasoningEffort(maximumOutputTokens)
}

func chatCompletionsMissingOutputMessage(providerName string, choices []chatCompletionsChoice, includeContent bool) string {
	details := make([]string, 0, len(choices))
	for index, choice := range choices {
		detail := fmt.Sprintf(
			"choice[%d]: finish=%q content_bytes=%d reasoning_bytes=%d",
			index,
			choice.FinishReason,
			len(choice.Message.Content),
			len(choice.Message.ReasoningContent),
		)
		if includeContent && choice.Message.Content != "" {
			detail += fmt.Sprintf(" content_preview=%q", boundedContentPreview(choice.Message.Content, 512))
		}
		details = append(details, detail)
	}
	if len(details) == 0 {
		return providerName + " response did not contain structured output (choices=0)"
	}
	return providerName + " response did not contain structured output (" + strings.Join(details, "; ") + ")"
}

func (p *FireworksProvider) responseFormat(schema any) map[string]any {
	return chatCompletionsResponseFormat(p.ResponseFormat, schema)
}

func (p *FireworksProvider) reasoningEffort(maximumOutputTokens int) string {
	return chatCompletionsReasoningEffort(p.ReasoningEffort, maximumOutputTokens)
}

func fireworksMissingOutputMessage(choices []chatCompletionsChoice, includeContent bool) string {
	return chatCompletionsMissingOutputMessage("fireworks", choices, includeContent)
}

func boundedContentPreview(content string, maximumBytes int) string {
	if len(content) <= maximumBytes {
		return content
	}
	return strings.ToValidUTF8(content[:maximumBytes], "�") + "…"
}

// compatibleStructuredOutput accepts raw JSON and common wrappers emitted by
// OpenAI-compatible servers that honor the schema semantically but not at the
// transport boundary. The broker still validates the extracted value against
// the requested schema before returning it to the adversary.
func compatibleStructuredOutput(content string) (json.RawMessage, bool) {
	trimmed := strings.TrimSpace(content)
	if json.Valid([]byte(trimmed)) {
		return json.RawMessage(trimmed), true
	}
	newline := strings.IndexByte(trimmed, '\n')
	if newline >= 0 && strings.HasSuffix(trimmed, "```") {
		opener := strings.TrimSpace(trimmed[:newline])
		if opener == "```" || strings.EqualFold(opener, "```json") {
			body := strings.TrimSpace(strings.TrimSuffix(trimmed[newline+1:], "```"))
			if json.Valid([]byte(body)) {
				return json.RawMessage(body), true
			}
		}
	}

	for index := range trimmed {
		if trimmed[index] != '{' && trimmed[index] != '[' {
			continue
		}
		decoder := json.NewDecoder(strings.NewReader(trimmed[index:]))
		var output json.RawMessage
		if err := decoder.Decode(&output); err == nil && json.Valid(output) {
			return output, true
		}
	}
	return nil, false
}

func defaultChatCompletionsReasoningEffort(maximumOutputTokens int) string {
	if maximumOutputTokens <= 2_000 {
		return "none"
	}
	return "low"
}

func fireworksReasoningEffort(maximumOutputTokens int) string {
	return defaultChatCompletionsReasoningEffort(maximumOutputTokens)
}

func chatCompletionsReviewInput(request Request) string {
	return "Review input:\n" + string(request.Input) +
		"\n\nReturn only JSON matching this schema:\n" + string(request.Schema)
}
