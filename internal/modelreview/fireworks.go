package modelreview

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type FireworksProvider struct {
	APIKey  string
	ModelID string
	BaseURL string
	Client  *http.Client
}

func (p *FireworksProvider) Name() string  { return "fireworks" }
func (p *FireworksProvider) Model() string { return p.ModelID }

func (p *FireworksProvider) Review(ctx context.Context, request Request) (Result, error) {
	var schema any
	if err := json.Unmarshal(request.Schema, &schema); err != nil {
		return Result{}, fmt.Errorf("decode model schema: %w", err)
	}
	payload := map[string]any{
		"model":      p.ModelID,
		"max_tokens": request.Budget.MaximumOutputTokens,
		"reasoning_effort": fireworksReasoningEffort(
			request.Budget.MaximumOutputTokens,
		),
		"messages": []map[string]any{
			{"role": "system", "content": request.Prompt},
			{"role": "user", "content": fireworksReviewInput(request)},
		},
		"response_format": map[string]any{
			"type": "json_schema",
			"json_schema": map[string]any{
				"name":   "adversary_model_review",
				"schema": schema,
			},
		},
	}
	data, status, err := postJSON(ctx, p.Client, p.BaseURL+"/v1/chat/completions", map[string]string{
		"authorization": "Bearer " + p.APIKey,
	}, payload)
	if err != nil {
		return Result{}, err
	}
	if status < 200 || status >= 300 {
		return Result{}, providerHTTPError(p.Name(), status, data)
	}
	var response struct {
		Choices []struct {
			Message struct {
				Content          string `json:"content"`
				ReasoningContent string `json:"reasoning_content"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return Result{}, fmt.Errorf("decode fireworks response: %w", err)
	}
	for _, choice := range response.Choices {
		if output, ok := compatibleStructuredOutput(choice.Message.Content); ok {
			return Result{
				Output: output,
				Usage:  Usage{InputTokens: response.Usage.PromptTokens, OutputTokens: response.Usage.CompletionTokens},
			}, nil
		}
	}
	return Result{}, &ProviderError{
		Code:    "fireworks_missing_output",
		Message: fireworksMissingOutputMessage(response.Choices),
	}
}

func fireworksMissingOutputMessage(choices []struct {
	Message struct {
		Content          string `json:"content"`
		ReasoningContent string `json:"reasoning_content"`
	} `json:"message"`
	FinishReason string `json:"finish_reason"`
}) string {
	details := make([]string, 0, len(choices))
	for index, choice := range choices {
		details = append(details, fmt.Sprintf(
			"choice[%d]: finish=%q content_bytes=%d reasoning_bytes=%d",
			index,
			choice.FinishReason,
			len(choice.Message.Content),
			len(choice.Message.ReasoningContent),
		))
	}
	if len(details) == 0 {
		return "fireworks response did not contain structured output (choices=0)"
	}
	return "fireworks response did not contain structured output (" + strings.Join(details, "; ") + ")"
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

func fireworksReasoningEffort(maximumOutputTokens int) string {
	if maximumOutputTokens <= 2_000 {
		return "none"
	}
	return "low"
}

func fireworksReviewInput(request Request) string {
	return "Review input:\n" + string(request.Input) +
		"\n\nReturn only JSON matching this schema:\n" + string(request.Schema)
}
