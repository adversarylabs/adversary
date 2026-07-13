// Package dependencies contains constructible function adapters for application ports.
// It deliberately provides no package-level defaults or process-global lookups.
package dependencies

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/pkg/adversarylabs"
)

type Clock struct {
	NowFunc   func() time.Time
	TimerFunc func(time.Duration) application.Timer
}

func (c Clock) Now() time.Time {
	if c.NowFunc == nil {
		return time.Time{}
	}
	return c.NowFunc()
}
func (c Clock) NewTimer(d time.Duration) application.Timer {
	if c.TimerFunc == nil {
		return nil
	}
	return c.TimerFunc(d)
}
func (c Clock) Validate() error {
	if c.NowFunc == nil || c.TimerFunc == nil {
		return fmt.Errorf("clock functions required")
	}
	return nil
}

type Environment struct{ LookupFunc func(string) (string, bool) }

func (e Environment) Lookup(key string) (string, bool) {
	if e.LookupFunc == nil {
		return "", false
	}
	return e.LookupFunc(key)
}
func (e Environment) Validate() error {
	if e.LookupFunc == nil {
		return fmt.Errorf("environment lookup function required")
	}
	return nil
}

type HTTPClient struct {
	DoFunc func(*http.Request) (*http.Response, error)
}

func (c HTTPClient) Do(r *http.Request) (*http.Response, error) {
	if c.DoFunc == nil {
		return nil, fmt.Errorf("HTTP function required")
	}
	return c.DoFunc(r)
}
func (c HTTPClient) Validate() error {
	if c.DoFunc == nil {
		return fmt.Errorf("HTTP function required")
	}
	return nil
}

type CallbackServer interface {
	Serve(net.Listener) error
	Shutdown(context.Context) error
}

type BrowserAuth struct {
	Entropy       io.Reader
	ListenFunc    func(string, string) (net.Listener, error)
	NewServerFunc func(http.Handler) CallbackServer
	OpenFunc      func(context.Context, string) error
}

func NewHTTPCallbackServer(handler http.Handler) CallbackServer {
	return &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, IdleTimeout: 15 * time.Second}
}

func (b BrowserAuth) Validate() error {
	if b.Entropy == nil || b.ListenFunc == nil || b.NewServerFunc == nil || b.OpenFunc == nil {
		return fmt.Errorf("browser auth entropy, listener, server, and browser functions required")
	}
	return nil
}

func (b BrowserAuth) Login(parent context.Context, request application.BrowserAuthRequest) (_ adversarylabs.TokenResponse, retErr error) {
	if err := b.Validate(); err != nil {
		return adversarylabs.TokenResponse{}, err
	}
	if request.Client == nil || request.Output == nil {
		return adversarylabs.TokenResponse{}, fmt.Errorf("browser auth client and output are required")
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Minute)
	defer cancel()
	state, err := randomURLToken(b.Entropy, 32)
	if err != nil {
		return adversarylabs.TokenResponse{}, fmt.Errorf("generate login state: %w", err)
	}
	verifier, err := randomURLToken(b.Entropy, 48)
	if err != nil {
		return adversarylabs.TokenResponse{}, fmt.Errorf("generate PKCE verifier: %w", err)
	}
	pathToken, err := randomURLToken(b.Entropy, 24)
	if err != nil {
		return adversarylabs.TokenResponse{}, fmt.Errorf("generate callback path: %w", err)
	}
	callbackPath := "/callback/" + pathToken
	challengeBytes := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(challengeBytes[:])
	listener, err := b.ListenFunc("tcp", "127.0.0.1:0")
	if err != nil {
		return adversarylabs.TokenResponse{}, fmt.Errorf("start local login callback: %w", err)
	}
	if listener == nil {
		return adversarylabs.TokenResponse{}, fmt.Errorf("start local login callback: listener is nil")
	}
	defer func() { retErr = errors.Join(retErr, normalizeCallbackCloseError(listener.Close())) }()
	if listener.Addr() == nil {
		return adversarylabs.TokenResponse{}, fmt.Errorf("start local login callback: listener address is nil")
	}
	host, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil || host != "127.0.0.1" || port == "" || port == "0" {
		return adversarylabs.TokenResponse{}, fmt.Errorf("local login callback did not bind exact IPv4 loopback")
	}
	result := make(chan browserLoginOutcome, 1)
	callbackURL := "http://" + net.JoinHostPort(host, port) + callbackPath
	mux := http.NewServeMux()
	mux.Handle(callbackPath, browserCallbackHandler(state, result, func(code string) (adversarylabs.TokenResponse, error) {
		return request.Client.ExchangeCode(ctx, code, verifier, callbackURL)
	}))
	server := b.NewServerFunc(mux)
	if server == nil {
		return adversarylabs.TokenResponse{}, fmt.Errorf("browser auth server factory returned nil")
	}
	go func() {
		serveErr := server.Serve(listener)
		if serveErr == nil {
			serveErr = errors.New("browser auth callback server stopped unexpectedly")
		}
		if err := normalizeCallbackCloseError(serveErr); err != nil {
			publishBrowserOutcome(result, browserLoginOutcome{err: fmt.Errorf("serve local login callback: %w", err)})
		}
	}()
	defer func() {
		shutdownCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer stop()
		retErr = errors.Join(retErr, normalizeCallbackCloseError(server.Shutdown(shutdownCtx)))
	}()
	loginURL, err := request.Client.BrowserLoginURL(adversarylabs.BrowserLoginOptions{RedirectURI: callbackURL, State: state, CodeChallenge: challenge, Name: request.Name, CI: request.CI})
	if err != nil {
		return adversarylabs.TokenResponse{}, err
	}
	fmt.Fprintln(request.Output, "Opening browser for Adversary Labs login...")
	fmt.Fprintln(request.Output)
	fmt.Fprintln(request.Output, loginURL)
	fmt.Fprintln(request.Output)
	if err := b.OpenFunc(ctx, loginURL); err != nil {
		fmt.Fprintf(request.Output, "Could not open browser automatically: %v\n", err)
		fmt.Fprintln(request.Output, "Open the URL above to continue.")
		fmt.Fprintln(request.Output)
	}
	fmt.Fprintln(request.Output, "Waiting for browser authentication...")
	select {
	case outcome := <-result:
		return outcome.token, outcome.err
	case <-ctx.Done():
		return adversarylabs.TokenResponse{}, ctx.Err()
	}
}

func normalizeCallbackCloseError(err error) error {
	if callbackCloseOnly(err) {
		return nil
	}
	return err
}

func callbackCloseOnly(err error) bool {
	if err == nil {
		return true
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		children := joined.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !callbackCloseOnly(child) {
				return false
			}
		}
		return true
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		return callbackCloseOnly(wrapped.Unwrap())
	}
	return errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed)
}

type browserLoginOutcome struct {
	token adversarylabs.TokenResponse
	err   error
}

func publishBrowserOutcome(ch chan<- browserLoginOutcome, outcome browserLoginOutcome) {
	select {
	case ch <- outcome:
	default:
	}
}

func browserCallbackHandler(state string, result chan<- browserLoginOutcome, exchange func(string) (adversarylabs.TokenResponse, error)) http.Handler {
	var claimed atomic.Bool
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			http.Error(w, "Method not allowed.", http.StatusMethodNotAllowed)
			return
		}
		query := request.URL.Query()
		states, statePresent := query["state"]
		if !statePresent || len(states) != 1 || states[0] != state {
			http.Error(w, "Invalid login state.", http.StatusBadRequest)
			return
		}
		if _, tokenPresent := query["token"]; tokenPresent {
			http.Error(w, "Login callback contained a forbidden token.", http.StatusBadRequest)
			return
		}
		if _, errorPresent := query["error"]; errorPresent {
			if !claimed.CompareAndSwap(false, true) {
				http.Error(w, "Login callback was already handled.", http.StatusConflict)
				return
			}
			publishBrowserOutcome(result, browserLoginOutcome{err: fmt.Errorf("login authorization failed")})
			http.Error(w, "Login failed. You can close this window.", http.StatusBadRequest)
			return
		}
		codes, codePresent := query["code"]
		if !codePresent || len(codes) != 1 || codes[0] == "" {
			http.Error(w, "Login callback was missing a code.", http.StatusBadRequest)
			return
		}
		code := codes[0]
		if !claimed.CompareAndSwap(false, true) {
			http.Error(w, "Login callback was already handled.", http.StatusConflict)
			return
		}
		token, err := exchange(code)
		if err != nil {
			publishBrowserOutcome(result, browserLoginOutcome{err: err})
			http.Error(w, "Login failed. You can close this window.", http.StatusBadGateway)
			return
		}
		publishBrowserOutcome(result, browserLoginOutcome{token: token})
		fmt.Fprintln(w, "Login complete. You can close this window.")
	})
}

func randomURLToken(entropy io.Reader, size int) (string, error) {
	buffer := make([]byte, size)
	if _, err := io.ReadFull(entropy, buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

var _ application.Clock = Clock{}
var _ application.Environment = Environment{}
var _ application.HTTPClient = HTTPClient{}
var _ application.BrowserAuth = BrowserAuth{}
