package modelreview

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

type OpenAIProvider struct {
	APIKey          string
	ModelID         string
	BaseURL         string
	ReasoningEffort string
	Client          *http.Client
}

func (p *OpenAIProvider) Name() string  { return "openai" }
func (p *OpenAIProvider) Model() string { return p.ModelID }

func (p *OpenAIProvider) Review(ctx context.Context, request Request) (Result, error) {
	var schema any
	if err := json.Unmarshal(request.Schema, &schema); err != nil {
		return Result{}, fmt.Errorf("decode model schema: %w", err)
	}
	payload := map[string]any{
		"model":             p.ModelID,
		"instructions":      request.Prompt,
		"input":             string(request.Input),
		"store":             false,
		"max_output_tokens": request.Budget.MaximumOutputTokens,
		"text": map[string]any{
			"format": map[string]any{
				"type":   "json_schema",
				"name":   "adversary_model_review",
				"strict": true,
				"schema": schema,
			},
		},
	}
	if p.ReasoningEffort != "" {
		payload["reasoning"] = map[string]any{"effort": p.ReasoningEffort}
	}
	data, status, err := postJSON(ctx, p.Client, p.BaseURL+"/v1/responses", map[string]string{
		"authorization": "Bearer " + p.APIKey,
	}, payload)
	if err != nil {
		return Result{}, err
	}
	if status < 200 || status >= 300 {
		return Result{}, providerHTTPError(p.Name(), status, data)
	}
	var response struct {
		Output []struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"output"`
		Usage struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return Result{}, fmt.Errorf("decode openai response: %w", err)
	}
	for _, item := range response.Output {
		for _, content := range item.Content {
			if content.Type == "output_text" && json.Valid([]byte(content.Text)) {
				return Result{
					Output: json.RawMessage(content.Text),
					Usage:  Usage{InputTokens: response.Usage.InputTokens, OutputTokens: response.Usage.OutputTokens},
				}, nil
			}
		}
	}
	return Result{}, &ProviderError{Code: "openai_missing_output", Message: "openai response did not contain structured output"}
}
