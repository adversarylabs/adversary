package modelreview

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Broker struct {
	Provider Provider
	// PromptSuffix is trusted caller-owned context appended to every package
	// model request. It is not exposed as a process environment variable.
	PromptSuffix string
	Entropy      io.Reader
	Listen       func(network, address string) (net.Listener, error)
}

type Session struct {
	Endpoint string
	Token    string

	server   *http.Server
	listener net.Listener
	done     chan error
	once     sync.Once
	closeErr error
}

func (b Broker) Start(ctx context.Context) (*Session, error) {
	if b.Provider == nil {
		return nil, fmt.Errorf("model provider is required")
	}
	entropy := b.Entropy
	if entropy == nil {
		entropy = rand.Reader
	}
	tokenBytes := make([]byte, 32)
	if _, err := io.ReadFull(entropy, tokenBytes); err != nil {
		return nil, fmt.Errorf("generate model broker token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	listen := b.Listen
	if listen == nil {
		listen = net.Listen
	}
	listener, err := listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("start model broker listener: %w", err)
	}
	session := &Session{
		Endpoint: "http://" + listener.Addr().String() + "/v1/review",
		Token:    token,
		listener: listener,
		done:     make(chan error, 1),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/review", session.reviewHandler(ctx, b.Provider, b.PromptSuffix))
	session.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      11 * time.Minute,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	go func() {
		err := session.server.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		session.done <- err
		close(session.done)
	}()
	return session, nil
}

func (s *Session) Close() error {
	s.once.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		s.closeErr = s.server.Shutdown(ctx)
		if s.closeErr != nil {
			_ = s.listener.Close()
		}
		if serveErr := <-s.done; s.closeErr == nil {
			s.closeErr = serveErr
		}
	})
	return s.closeErr
}

func (s *Session) reviewHandler(parent context.Context, provider Provider, promptSuffix string) http.HandlerFunc {
	return func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("content-type", "application/json")
		response.Header().Set("cache-control", "no-store")
		if request.Method != http.MethodPost {
			response.Header().Set("allow", http.MethodPost)
			writeError(response, http.StatusMethodNotAllowed, "method_not_allowed", "Model broker accepts POST requests only.", false)
			return
		}
		if request.Header.Get("x-adversary-model-protocol") != fmt.Sprint(ProtocolVersion) {
			writeError(response, http.StatusBadRequest, "unsupported_model_protocol", "Unsupported model broker protocol.", false)
			return
		}
		token := strings.TrimPrefix(request.Header.Get("authorization"), "Bearer ")
		if len(token) != len(s.Token) || subtle.ConstantTimeCompare([]byte(token), []byte(s.Token)) != 1 {
			writeError(response, http.StatusUnauthorized, "invalid_broker_token", "Model broker authentication failed.", false)
			return
		}
		data, err := io.ReadAll(io.LimitReader(request.Body, MaxRequestBytes+1))
		if err != nil {
			writeError(response, http.StatusBadRequest, "invalid_model_request", "Could not read model review request.", false)
			return
		}
		if len(data) > MaxRequestBytes {
			writeError(response, http.StatusRequestEntityTooLarge, "model_request_too_large", fmt.Sprintf("Model review request exceeds %d bytes.", MaxRequestBytes), false)
			return
		}
		modelRequest, err := DecodeRequest(data)
		if err != nil {
			writeError(response, http.StatusBadRequest, "invalid_model_request", err.Error(), false)
			return
		}
		if suffix := strings.TrimSpace(promptSuffix); suffix != "" {
			const separator = "\n\n---\n\n"
			prompt := strings.TrimSpace(modelRequest.Prompt)
			available := MaxPromptBytes - len(prompt) - len(separator)
			if available > 0 {
				if len(suffix) > available {
					suffix = strings.ToValidUTF8(suffix[:available], "")
				}
				modelRequest.Prompt = prompt + separator + suffix
			}
		}
		timeout := time.Duration(modelRequest.Budget.TimeoutMS) * time.Millisecond
		reviewContext, cancel := context.WithTimeout(parent, timeout)
		defer cancel()
		result, err := provider.Review(reviewContext, modelRequest)
		if err != nil {
			var providerErr *ProviderError
			if errors.As(err, &providerErr) {
				status := http.StatusBadGateway
				if providerErr.StatusCode == http.StatusTooManyRequests {
					status = http.StatusTooManyRequests
				}
				writeError(response, status, providerErr.Code, providerErr.Message, providerErr.Retryable)
				return
			}
			if errors.Is(err, context.DeadlineExceeded) {
				writeError(response, http.StatusGatewayTimeout, "model_timeout", "Model review timed out.", true)
				return
			}
			if errors.Is(err, context.Canceled) {
				writeError(response, http.StatusServiceUnavailable, "model_canceled", "Model review was canceled.", true)
				return
			}
			writeError(response, http.StatusBadGateway, "model_provider_failure", err.Error(), true)
			return
		}
		if len(result.Output) == 0 || len(result.Output) > MaxProviderBytes {
			writeError(response, http.StatusBadGateway, "invalid_model_output", "Model provider returned an empty or oversized output.", false)
			return
		}
		if err := ValidateOutput(modelRequest.Schema, result.Output); err != nil {
			writeError(response, http.StatusBadGateway, "invalid_model_output", err.Error(), false)
			return
		}
		envelope := Response{
			ProtocolVersion: ProtocolVersion,
			Output:          result.Output,
			Provider:        provider.Name(),
			Model:           provider.Model(),
		}
		if result.Usage.InputTokens > 0 || result.Usage.OutputTokens > 0 {
			usage := result.Usage
			envelope.Usage = &usage
		}
		response.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(response).Encode(envelope)
	}
}

func writeError(response http.ResponseWriter, status int, code, message string, retryable bool) {
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(ErrorResponse{
		Error: ErrorBody{Code: code, Message: message, Retryable: retryable},
	})
}
