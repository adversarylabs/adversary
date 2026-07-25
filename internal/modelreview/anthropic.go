package modelreview

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

type AnthropicProvider struct {
	APIKey  string
	ModelID string
	BaseURL string
	Client  *http.Client
}

func (p *AnthropicProvider) Name() string  { return "anthropic" }
func (p *AnthropicProvider) Model() string { return p.ModelID }

func (p *AnthropicProvider) Review(ctx context.Context, request Request) (Result, error) {
	var schema any
	if err := json.Unmarshal(request.Schema, &schema); err != nil {
		return Result{}, fmt.Errorf("decode model schema: %w", err)
	}
	payload := map[string]any{
		"model":      p.ModelID,
		"max_tokens": request.Budget.MaximumOutputTokens,
		"system":     request.Prompt,
		"messages": []map[string]any{{
			"role":    "user",
			"content": string(request.Input),
		}},
		"tools": []map[string]any{{
			"name":         "submit_review",
			"description":  "Return the structured adversary review.",
			"input_schema": schema,
		}},
		"tool_choice": map[string]any{"type": "tool", "name": "submit_review"},
	}
	data, status, err := postJSON(ctx, p.Client, p.BaseURL+"/v1/messages", map[string]string{
		"x-api-key":         p.APIKey,
		"anthropic-version": "2023-06-01",
	}, payload)
	if err != nil {
		return Result{}, err
	}
	if status < 200 || status >= 300 {
		return Result{}, providerHTTPError(p.Name(), status, data)
	}
	var response struct {
		Content []struct {
			Type  string          `json:"type"`
			Name  string          `json:"name"`
			Input json.RawMessage `json:"input"`
		} `json:"content"`
		Usage struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return Result{}, fmt.Errorf("decode anthropic response: %w", err)
	}
	for _, content := range response.Content {
		if content.Type == "tool_use" && content.Name == "submit_review" && json.Valid(content.Input) {
			return Result{
				Output: content.Input,
				Usage:  Usage{InputTokens: response.Usage.InputTokens, OutputTokens: response.Usage.OutputTokens},
			}, nil
		}
	}
	return Result{}, &ProviderError{Code: "anthropic_missing_output", Message: "anthropic response did not contain structured output"}
}
