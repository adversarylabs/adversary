// Package modelreview owns the provider-neutral model broker used by adversary
// child processes. Provider credentials never cross the process boundary.
package modelreview

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const (
	ProtocolVersion     = 1
	MaxRequestBytes     = 5 << 20
	MaxProviderBytes    = 4 << 20
	MaxPromptBytes      = 256 << 10
	MaxInputBytes       = 4 << 20
	MaxSchemaBytes      = 512 << 10
	MaxOutputTokens     = 65_536
	MaxRequestTimeoutMS = 10 * 60 * 1_000
)

type Budget struct {
	MaximumOutputTokens int `json:"maximumOutputTokens"`
	TimeoutMS           int `json:"timeoutMs"`
}

type Request struct {
	ProtocolVersion int             `json:"protocolVersion"`
	Prompt          string          `json:"prompt"`
	Input           json.RawMessage `json:"input"`
	Schema          json.RawMessage `json:"schema"`
	Budget          Budget          `json:"budget"`
}

type Usage struct {
	InputTokens  int `json:"inputTokens,omitempty"`
	OutputTokens int `json:"outputTokens,omitempty"`
}

type Result struct {
	Output json.RawMessage
	Usage  Usage
}

type Response struct {
	ProtocolVersion int             `json:"protocolVersion"`
	Output          json.RawMessage `json:"output"`
	Provider        string          `json:"provider"`
	Model           string          `json:"model"`
	Usage           *Usage          `json:"usage,omitempty"`
}

type ErrorResponse struct {
	Error ErrorBody `json:"error"`
}

type ErrorBody struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

type Provider interface {
	Name() string
	Model() string
	Review(context.Context, Request) (Result, error)
}

type ProviderError struct {
	Code       string
	Message    string
	Retryable  bool
	StatusCode int
}

func (e *ProviderError) Error() string { return e.Message }

func DecodeRequest(data []byte) (Request, error) {
	if len(data) == 0 {
		return Request{}, fmt.Errorf("model review request is empty")
	}
	if len(data) > MaxRequestBytes {
		return Request{}, fmt.Errorf("model review request exceeds %d bytes", MaxRequestBytes)
	}
	var request Request
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return Request{}, fmt.Errorf("decode model review request: %w", err)
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return Request{}, fmt.Errorf("unexpected data after model review request")
		}
		return Request{}, fmt.Errorf("decode trailing model review request data: %w", err)
	}
	if request.ProtocolVersion != ProtocolVersion {
		return Request{}, fmt.Errorf("unsupported model protocolVersion %d", request.ProtocolVersion)
	}
	if request.Prompt == "" {
		return Request{}, fmt.Errorf("model review prompt is required")
	}
	if len([]byte(request.Prompt)) > MaxPromptBytes {
		return Request{}, fmt.Errorf("model review prompt exceeds %d bytes", MaxPromptBytes)
	}
	if len(request.Input) == 0 || string(request.Input) == "null" {
		return Request{}, fmt.Errorf("model review input is required")
	}
	if len(request.Input) > MaxInputBytes {
		return Request{}, fmt.Errorf("model review input exceeds %d bytes", MaxInputBytes)
	}
	if !json.Valid(request.Input) {
		return Request{}, fmt.Errorf("model review input must be valid JSON")
	}
	if len(request.Schema) == 0 || string(request.Schema) == "null" {
		return Request{}, fmt.Errorf("model review schema is required")
	}
	if len(request.Schema) > MaxSchemaBytes {
		return Request{}, fmt.Errorf("model review schema exceeds %d bytes", MaxSchemaBytes)
	}
	var schemaObject map[string]any
	if err := json.Unmarshal(request.Schema, &schemaObject); err != nil {
		return Request{}, fmt.Errorf("model review schema must be a JSON object: %w", err)
	}
	if request.Budget.MaximumOutputTokens < 1 || request.Budget.MaximumOutputTokens > MaxOutputTokens {
		return Request{}, fmt.Errorf("model review budget.maximumOutputTokens must be between 1 and %d", MaxOutputTokens)
	}
	if request.Budget.TimeoutMS < 1 || request.Budget.TimeoutMS > MaxRequestTimeoutMS {
		return Request{}, fmt.Errorf("model review budget.timeoutMs must be between 1 and %d", MaxRequestTimeoutMS)
	}
	if _, err := compileSchema(schemaObject); err != nil {
		return Request{}, fmt.Errorf("compile model review schema: %w", err)
	}
	return request, nil
}

func ValidateOutput(schemaData, output json.RawMessage) error {
	var schemaObject any
	if err := json.Unmarshal(schemaData, &schemaObject); err != nil {
		return fmt.Errorf("decode model review schema: %w", err)
	}
	schema, err := compileSchema(schemaObject)
	if err != nil {
		return fmt.Errorf("compile model review schema: %w", err)
	}
	var value any
	if err := json.Unmarshal(output, &value); err != nil {
		return fmt.Errorf("decode model output: %w", err)
	}
	if err := schema.Validate(value); err != nil {
		return fmt.Errorf("model output does not match requested schema: %w", err)
	}
	return nil
}

func compileSchema(document any) (*jsonschema.Schema, error) {
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	const resource = "urn:adversary:model-review-schema"
	if err := compiler.AddResource(resource, document); err != nil {
		return nil, err
	}
	return compiler.Compile(resource)
}
