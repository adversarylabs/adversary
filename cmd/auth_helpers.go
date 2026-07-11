package cmd

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/adversarylabs/adversary/internal/application"
	"github.com/adversarylabs/adversary/pkg/adversarylabs"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

func waitForLogin(ctx context.Context, clock application.Clock, client application.APIClient, login adversarylabs.DeviceLogin) (adversarylabs.TokenResponse, error) {
	interval := adversarylabs.PollInterval(login)
	expiresAt := clock.Now().Add(time.Duration(login.ExpiresIn) * time.Second)
	if login.ExpiresIn <= 0 {
		expiresAt = clock.Now().Add(10 * time.Minute)
	}
	pollCtx, cancel := context.WithDeadline(ctx, expiresAt)
	defer cancel()
	for {
		if err := pollCtx.Err(); err != nil {
			if ctx.Err() != nil {
				return adversarylabs.TokenResponse{}, ctx.Err()
			}
			return adversarylabs.TokenResponse{}, fmt.Errorf("login expired before authentication completed")
		}
		token, err := client.PollToken(pollCtx, login.DeviceCode)
		if err == nil {
			return token, nil
		}
		if pollCtx.Err() != nil {
			if ctx.Err() != nil {
				return adversarylabs.TokenResponse{}, ctx.Err()
			}
			return adversarylabs.TokenResponse{}, fmt.Errorf("login expired before authentication completed")
		}
		timer := clock.NewTimer(interval)
		select {
		case <-pollCtx.Done():
			timer.Stop()
			if ctx.Err() != nil {
				return adversarylabs.TokenResponse{}, ctx.Err()
			}
			return adversarylabs.TokenResponse{}, fmt.Errorf("login expired before authentication completed")
		case <-timer.C():
		}
	}
}

func loginWithDevice(ctx context.Context, clock application.Clock, stdout io.Writer, client application.APIClient, opts *loginOptions) (adversarylabs.TokenResponse, error) {
	login, err := client.BeginLogin(ctx, adversarylabs.LoginOptions{Name: opts.name, CI: opts.ci})
	if err != nil {
		return adversarylabs.TokenResponse{}, err
	}
	verificationURL := login.VerificationURIComplete
	if verificationURL == "" {
		verificationURL = login.VerificationURI
	}
	if verificationURL == "" || login.UserCode == "" {
		return adversarylabs.TokenResponse{}, fmt.Errorf("device login response was missing verification instructions")
	}
	fmt.Fprintf(stdout, "Open %s\n\nEnter code: %s\n\nWaiting for authentication...\n", verificationURL, login.UserCode)
	return waitForLogin(ctx, clock, client, login)
}

func loginWithBrowser(ctx context.Context, browser application.Browser, stdout io.Writer, client application.APIClient, opts *loginOptions) (adversarylabs.TokenResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	state, err := randomURLToken(32)
	if err != nil {
		return adversarylabs.TokenResponse{}, fmt.Errorf("generate login state: %w", err)
	}
	verifier, err := randomURLToken(48)
	if err != nil {
		return adversarylabs.TokenResponse{}, fmt.Errorf("generate PKCE verifier: %w", err)
	}
	pathToken, err := randomURLToken(24)
	if err != nil {
		return adversarylabs.TokenResponse{}, fmt.Errorf("generate callback path: %w", err)
	}
	callbackPath := "/callback/" + pathToken
	challengeBytes := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(challengeBytes[:])
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return adversarylabs.TokenResponse{}, fmt.Errorf("start local login callback: %w", err)
	}
	defer listener.Close()

	result := make(chan browserLoginOutcome, 1)
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, IdleTimeout: 15 * time.Second}
	mux := http.NewServeMux()
	server.Handler = mux
	callbackURL := "http://" + listener.Addr().String() + callbackPath
	mux.Handle(callbackPath, browserCallbackHandler(state, result, func(code string) (adversarylabs.TokenResponse, error) {
		return client.ExchangeCode(ctx, code, verifier, callbackURL)
	}))
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			publishBrowserOutcome(result, browserLoginOutcome{err: err})
		}
	}()
	defer func() {
		shutdownCtx, stop := context.WithTimeout(context.Background(), 2*time.Second)
		defer stop()
		_ = server.Shutdown(shutdownCtx)
	}()

	loginURL, err := client.BrowserLoginURL(adversarylabs.BrowserLoginOptions{
		RedirectURI:   callbackURL,
		State:         state,
		CodeChallenge: challenge,
		Name:          opts.name,
		CI:            opts.ci,
	})
	if err != nil {
		return adversarylabs.TokenResponse{}, err
	}
	fmt.Fprintln(stdout, "Opening browser for Adversary Labs login...")
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, loginURL)
	fmt.Fprintln(stdout)
	if err := browser.Open(ctx, loginURL); err != nil {
		fmt.Fprintf(stdout, "Could not open browser automatically: %v\n", err)
		fmt.Fprintln(stdout, "Open the URL above to continue.")
		fmt.Fprintln(stdout)
	}
	fmt.Fprintln(stdout, "Waiting for browser authentication...")
	select {
	case outcome := <-result:
		return outcome.token, outcome.err
	case <-ctx.Done():
		return adversarylabs.TokenResponse{}, ctx.Err()
	}
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
	var once sync.Once
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			http.Error(w, "Method not allowed.", http.StatusMethodNotAllowed)
			return
		}
		query := req.URL.Query()
		if query.Get("state") != state {
			http.Error(w, "Invalid login state.", http.StatusBadRequest)
			return
		}
		if query.Get("error") != "" {
			handled := false
			once.Do(func() {
				handled = true
				publishBrowserOutcome(result, browserLoginOutcome{err: fmt.Errorf("login authorization failed")})
				http.Error(w, "Login failed. You can close this window.", http.StatusBadRequest)
			})
			if !handled {
				http.Error(w, "Login callback was already handled.", http.StatusConflict)
			}
			return
		}
		code := query.Get("code")
		if code == "" || query.Get("token") != "" {
			http.Error(w, "Login callback was missing a code.", http.StatusBadRequest)
			return
		}
		handled := false
		once.Do(func() {
			handled = true
			token, err := exchange(code)
			if err != nil {
				publishBrowserOutcome(result, browserLoginOutcome{err: err})
				http.Error(w, "Login failed. You can close this window.", http.StatusBadGateway)
				return
			}
			publishBrowserOutcome(result, browserLoginOutcome{token: token})
			fmt.Fprintln(w, "Login complete. You can close this window.")
		})
		if !handled {
			http.Error(w, "Login callback was already handled.", http.StatusConflict)
		}
	})
}

func randomURLToken(size int) (string, error) {
	b := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func readPasswordLine(r io.Reader) (string, error) {
	data, err := io.ReadAll(io.LimitReader(r, 64*1024))
	if err != nil {
		return "", err
	}
	password := strings.TrimRight(string(data), "\r\n")
	if password == "" {
		return "", fmt.Errorf("password from standard input is empty")
	}
	return password, nil
}
