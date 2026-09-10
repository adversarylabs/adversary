package modelreview

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

type OpenAIProvider struct {
	ReasoningEffort string
	MaxOutputTokens int
	APIKey          string
	ModelID         string
	BaseURL         string
	Client          *http.Client
}

func (p *OpenAIProvider) Name() string  { return "openai" }
func (p *OpenAIProvider) Model() string { return p.ModelID }

func (p *OpenAIProvider) Review(ctx context.Context, request Request) (Result, error) {
	var schema any
	if err := json.Unmarshal(request.Schema, &schema); err != nil {
		return Result{}, fmt.Errorf("decode model schema: %w", err)
	}
	effort, maxTokens := p.requestSettings(request.Budget.MaximumOutputTokens)
	payload := map[string]any{
		"model":             p.ModelID,
		"instructions":      request.Prompt,
		"input":             string(request.Input),
		"store":             false,
		"max_output_tokens": maxTokens,
		"text": map[string]any{
			"format": map[string]any{
				"type":   "json_schema",
				"name":   "adversary_model_review",
				"strict": true,
				"schema": schema,
			},
		},
	}
	if effort != "" {
		payload["reasoning"] = map[string]any{"effort": effort}
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
		Status            string `json:"status"`
		IncompleteDetails struct {
			Reason string `json:"reason"`
		} `json:"incomplete_details"`
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
	if response.Status == "incomplete" {
		code := "openai_incomplete_output"
		if response.IncompleteDetails.Reason == "max_output_tokens" {
			code = "openai_output_token_limit"
		}
		return Result{}, &ProviderError{Code: code, Message: fmt.Sprintf("openai review incomplete: %s (max_output_tokens=%d, reasoning_effort=%q); reasoning and final output share this budget; configure %s or %s", response.IncompleteDetails.Reason, maxTokens, effort, OpenAIMaxOutputTokensEnv, OpenAIReasoningEffortEnv)}
	}
	if response.Status != "" && response.Status != "completed" {
		return Result{}, &ProviderError{Code: "openai_incomplete_output", Message: fmt.Sprintf("openai review did not complete (status=%q)", response.Status)}
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

// Luna uses the same output budget for reasoning and the structured answer.
// Treat the adversary's requested budget as the baseline, then add bounded
// headroom. Explicit provider settings always win; other models keep their
// existing defaults. Disabling reasoning also disables automatic headroom.
func (p *OpenAIProvider) requestSettings(requested int) (string, int) {
	effort, tokens := p.ReasoningEffort, requested
	if p.ModelID == "gpt-5.6-luna" {
		if effort == "" {
			effort = "high"
		}
		if effort != "none" {
			tokens = 16384
			if requested >= MaxOutputTokens/4 {
				tokens = MaxOutputTokens
			} else if requested > tokens/4 {
				tokens = requested * 4
			}
		}
	}
	if p.MaxOutputTokens > 0 {
		tokens = p.MaxOutputTokens
	}
	return effort, tokens
}
