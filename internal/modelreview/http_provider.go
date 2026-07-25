package modelreview

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func postJSON(ctx context.Context, client *http.Client, endpoint string, headers map[string]string, request any) ([]byte, int, error) {
	if client == nil {
		client = http.DefaultClient
	}
	body, err := json.Marshal(request)
	if err != nil {
		return nil, 0, fmt.Errorf("encode provider request: %w", err)
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, 0, fmt.Errorf("create provider request: %w", err)
	}
	httpRequest.Header.Set("content-type", "application/json")
	httpRequest.Header.Set("accept", "application/json")
	for name, value := range headers {
		httpRequest.Header.Set(name, value)
	}
	response, err := client.Do(httpRequest)
	if err != nil {
		return nil, 0, fmt.Errorf("call model provider: %w", err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, MaxProviderBytes+1))
	if err != nil {
		return nil, response.StatusCode, fmt.Errorf("read model provider response: %w", err)
	}
	if len(data) > MaxProviderBytes {
		return nil, response.StatusCode, fmt.Errorf("model provider response exceeds %d bytes", MaxProviderBytes)
	}
	return data, response.StatusCode, nil
}

func providerHTTPError(provider string, status int, data []byte) error {
	message := strings.TrimSpace(http.StatusText(status))
	var envelope struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(data, &envelope) == nil && strings.TrimSpace(envelope.Error.Message) != "" {
		message = strings.TrimSpace(envelope.Error.Message)
	}
	if message == "" {
		message = "model provider request failed"
	}
	return &ProviderError{
		Code:       provider + "_http_error",
		Message:    fmt.Sprintf("%s model request failed: %s", provider, message),
		Retryable:  status == http.StatusTooManyRequests || status >= 500,
		StatusCode: status,
	}
}
