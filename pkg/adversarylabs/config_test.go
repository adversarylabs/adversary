package adversarylabs

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveAPIURLDefaultEnvAndOverride(t *testing.T) {
	t.Setenv("ADVERSARY_API_URL", "")
	if got := ResolveAPIURL(""); got != "https://adversarylabs.ai/api" {
		t.Fatalf("default API URL = %q", got)
	}
	t.Setenv("ADVERSARY_API_URL", "http://localhost:3000/api/")
	if got := ResolveAPIURL(""); got != "http://localhost:3000/api" {
		t.Fatalf("env API URL = %q", got)
	}
	if got := ResolveAPIURL("http://127.0.0.1:8787/api/"); got != "http://127.0.0.1:8787/api" {
		t.Fatalf("override API URL = %q", got)
	}
}

func TestConfigStoreTokenStorageAndLogoutCleanup(t *testing.T) {
	store := ConfigStore{Path: filepath.Join(t.TempDir(), "config.json")}
	auth := Auth{
		Token:     "secret-token",
		ClientID:  "client-123",
		ExpiresAt: "2099-01-01T00:00:00Z",
	}
	if err := store.SetAuth(DefaultRegistry, auth); err != nil {
		t.Fatal(err)
	}
	got, ok := store.Auth(DefaultRegistry)
	if !ok {
		t.Fatal("expected stored auth")
	}
	if got.Token != auth.Token || got.ClientID != auth.ClientID || got.ExpiresAt != auth.ExpiresAt {
		t.Fatalf("stored auth = %#v", got)
	}
	removed, ok, err := store.RemoveAuth(DefaultRegistry)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || removed.Token != auth.Token {
		t.Fatalf("removed auth = %#v, %v", removed, ok)
	}
	if _, ok := store.Auth(DefaultRegistry); ok {
		t.Fatal("expected auth to be removed")
	}
}

func TestClientBeginLoginSendsNameAndCI(t *testing.T) {
	var seenPath string
	var seenBody map[string]any
	client := Client{
		BaseURL: "https://api.test",
		HTTP: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			seenPath = req.URL.Path
			if err := json.NewDecoder(req.Body).Decode(&seenBody); err != nil {
				return nil, err
			}
			return jsonResponse(http.StatusOK, `{
				"device_code": "device",
				"user_code": "ABCD",
				"verification_uri": "https://auth.test/device",
				"interval": 1
			}`), nil
		})},
	}
	login, err := client.BeginLogin(context.Background(), LoginOptions{Name: "Marc's MacBook Pro", CI: true})
	if err != nil {
		t.Fatal(err)
	}
	if seenPath != "/v1/auth/device/code" {
		t.Fatalf("path = %q", seenPath)
	}
	if seenBody["name"] != "Marc's MacBook Pro" || seenBody["ci"] != true {
		t.Fatalf("login body = %#v", seenBody)
	}
	if login.DeviceCode != "device" || login.UserCode != "ABCD" {
		t.Fatalf("login response = %#v", login)
	}
}

func TestClientLoginWithPassword(t *testing.T) {
	var seenPath string
	var seenBody map[string]any
	client := Client{
		BaseURL: "http://localhost:3000/api",
		HTTP: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			seenPath = req.URL.Path
			if err := json.NewDecoder(req.Body).Decode(&seenBody); err != nil {
				return nil, err
			}
			return jsonResponse(http.StatusOK, `{"token":"secret-token","client_id":"client-123","expires_at":"2099-01-01T00:00:00Z"}`), nil
		})},
	}
	token, err := client.LoginWithPassword(context.Background(), PasswordLoginOptions{
		EmailAddress: "marc@example.com",
		Password:     "secret",
		Name:         "Marc's MacBook Pro",
		CI:           true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if seenPath != "/api/v1/auth/login" {
		t.Fatalf("path = %q", seenPath)
	}
	if seenBody["email_address"] != "marc@example.com" || seenBody["email"] != "marc@example.com" || seenBody["password"] != "secret" || seenBody["ci"] != true {
		t.Fatalf("login body = %#v", seenBody)
	}
	if token.Token != "secret-token" || token.ClientID != "client-123" {
		t.Fatalf("token = %#v", token)
	}
}

func TestClientBrowserLoginURL(t *testing.T) {
	client := Client{BaseURL: "http://localhost:3000/api"}
	loginURL, err := client.BrowserLoginURL(BrowserLoginOptions{
		RedirectURI: "http://127.0.0.1:54321/callback",
		Name:        "Marc's MacBook Pro",
		CI:          true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(loginURL, "http://localhost:3000/login?") {
		t.Fatalf("login URL = %q", loginURL)
	}
	if !strings.Contains(loginURL, "next=http%3A%2F%2F127.0.0.1%3A54321%2Fcallback") {
		t.Fatalf("login URL missing next callback: %q", loginURL)
	}
	if strings.Contains(loginURL, "/api/login") {
		t.Fatalf("login URL should use app URL, not API URL: %q", loginURL)
	}
}

func TestClientSearchUsesStoredToken(t *testing.T) {
	var authHeader string
	client := Client{
		BaseURL: "https://api.test",
		HTTP: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			authHeader = req.Header.Get("Authorization")
			if req.URL.Query().Get("q") != "dockerfile" {
				t.Fatalf("query = %q", req.URL.RawQuery)
			}
			return jsonResponse(http.StatusOK, `{"results":[{"name":"adversarylabs/dockerfile","version":"1.0.0"}]}`), nil
		})},
	}
	results, err := client.Search(context.Background(), "dockerfile", "secret-token")
	if err != nil {
		t.Fatal(err)
	}
	if authHeader != "Bearer secret-token" {
		t.Fatalf("authorization header = %q", authHeader)
	}
	if len(results) != 1 || results[0].Name != "adversarylabs/dockerfile" {
		t.Fatalf("results = %#v", results)
	}
}

func TestClientWhoamiUsesBearerToken(t *testing.T) {
	var seenPath string
	var authHeader string
	client := Client{
		BaseURL: "http://localhost:3000/api",
		HTTP: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			seenPath = req.URL.Path
			authHeader = req.Header.Get("Authorization")
			return jsonResponse(http.StatusOK, `{
				"name": "Marc",
				"email": "marc@example.com",
				"subscription": {
					"plan": "Pro",
					"status": "active"
				}
			}`), nil
		})},
	}
	account, err := client.Whoami(context.Background(), "secret-token")
	if err != nil {
		t.Fatal(err)
	}
	if seenPath != "/api/v1/auth/whoami" {
		t.Fatalf("path = %q", seenPath)
	}
	if authHeader != "Bearer secret-token" {
		t.Fatalf("authorization header = %q", authHeader)
	}
	if account.Email != "marc@example.com" || account.Subscription.Plan != "Pro" || account.Subscription.Status != "active" {
		t.Fatalf("account = %#v", account)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewBufferString(strings.TrimSpace(body))),
	}
}
