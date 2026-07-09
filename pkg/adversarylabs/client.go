package adversarylabs

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type Client struct {
	BaseURL string
	HTTP    *http.Client
	Store   ConfigStore
}

type LoginOptions struct {
	Name string `json:"name,omitempty"`
	CI   bool   `json:"ci,omitempty"`
}

type PasswordLoginOptions struct {
	EmailAddress string `json:"email_address"`
	Email        string `json:"email,omitempty"`
	Password     string `json:"password"`
	Name         string `json:"name,omitempty"`
	CI           bool   `json:"ci,omitempty"`
}

type DeviceLogin struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

type TokenResponse struct {
	Token             string `json:"token"`
	ClientID          string `json:"client_id"`
	ExpiresAt         string `json:"expires_at"`
	RegistryNamespace string `json:"registry_namespace,omitempty"`
	Namespace         string `json:"namespace,omitempty"`
	Team              string `json:"team,omitempty"`
}

type BrowserLoginOptions struct {
	RedirectURI string
	Name        string
	CI          bool
}

type SearchResult struct {
	Name        string `json:"name"`
	Version     string `json:"version,omitempty"`
	Description string `json:"description,omitempty"`
	Reference   string `json:"reference,omitempty"`
}

type WhoamiResponse struct {
	ID                string       `json:"id,omitempty"`
	Name              string       `json:"name,omitempty"`
	Email             string       `json:"email,omitempty"`
	EmailAddress      string       `json:"email_address,omitempty"`
	RegistryNamespace string       `json:"registry_namespace,omitempty"`
	Namespace         string       `json:"namespace,omitempty"`
	Team              Team         `json:"team,omitempty"`
	Teams             []Team       `json:"teams,omitempty"`
	Organization      Team         `json:"organization,omitempty"`
	Subscription      Subscription `json:"subscription,omitempty"`
}

type Team struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	Slug string `json:"slug,omitempty"`
}

type Subscription struct {
	Name   string `json:"name,omitempty"`
	Plan   string `json:"plan,omitempty"`
	Status string `json:"status,omitempty"`
}

func NewClient(store ConfigStore) Client {
	return Client{BaseURL: ResolveAPIURL(""), HTTP: http.DefaultClient, Store: store}
}

func NewClientWithBaseURL(store ConfigStore, baseURL string) Client {
	return Client{BaseURL: ResolveAPIURL(baseURL), HTTP: http.DefaultClient, Store: store}
}

func ResolveAPIURL(override string) string {
	if value := strings.TrimSpace(override); value != "" {
		return strings.TrimRight(value, "/")
	}
	if env := strings.TrimSpace(os.Getenv("ADVERSARY_API_URL")); env != "" {
		return strings.TrimRight(env, "/")
	}
	return strings.TrimRight(DefaultAPIURL, "/")
}

func (c Client) BeginLogin(ctx context.Context, opts LoginOptions) (DeviceLogin, error) {
	var out DeviceLogin
	if err := c.postJSON(ctx, "/v1/auth/device/code", opts, "", &out); err != nil {
		return DeviceLogin{}, err
	}
	return out, nil
}

func (c Client) LoginWithPassword(ctx context.Context, opts PasswordLoginOptions) (TokenResponse, error) {
	opts.Email = opts.EmailAddress
	var out TokenResponse
	if err := c.postJSON(ctx, "/v1/auth/login", opts, "", &out); err != nil {
		return TokenResponse{}, err
	}
	if out.Token == "" {
		return TokenResponse{}, fmt.Errorf("login response did not include a token")
	}
	return out, nil
}

func (c Client) BrowserLoginURL(opts BrowserLoginOptions) (string, error) {
	appBase := appBaseURL(c.BaseURL)
	u, err := url.Parse(appBase + "/login")
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("next", opts.RedirectURI)
	q.Set("redirect_uri", opts.RedirectURI)
	q.Set("cli", "true")
	if opts.Name != "" {
		q.Set("name", opts.Name)
	}
	if opts.CI {
		q.Set("ci", "true")
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (c Client) ExchangeCode(ctx context.Context, code string) (TokenResponse, error) {
	var out TokenResponse
	if err := c.postJSON(ctx, "/v1/auth/cli/exchange", map[string]string{"code": code}, "", &out); err != nil {
		return TokenResponse{}, err
	}
	if out.Token == "" {
		return TokenResponse{}, fmt.Errorf("login response did not include a token")
	}
	return out, nil
}

func (c Client) PollToken(ctx context.Context, deviceCode string) (TokenResponse, error) {
	payload := map[string]string{"device_code": deviceCode}
	var out TokenResponse
	if err := c.postJSON(ctx, "/v1/auth/device/token", payload, "", &out); err != nil {
		return TokenResponse{}, err
	}
	if out.Token == "" {
		return TokenResponse{}, fmt.Errorf("login response did not include a token")
	}
	return out, nil
}

func appBaseURL(apiBase string) string {
	apiBase = strings.TrimRight(apiBase, "/")
	if strings.HasSuffix(apiBase, "/api") {
		return strings.TrimSuffix(apiBase, "/api")
	}
	return apiBase
}

func (c Client) Revoke(ctx context.Context, token string) error {
	return c.postJSON(ctx, "/v1/auth/revoke", map[string]string{"token": token}, token, nil)
}

func (c Client) Search(ctx context.Context, query string, token string) ([]SearchResult, error) {
	u, err := url.Parse(c.BaseURL + "/v1/search")
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("q", query)
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("search requires login; run adversary login")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("search failed: %s", resp.Status)
	}
	var body struct {
		Results []SearchResult `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	return body.Results, nil
}

func (c Client) Whoami(ctx context.Context, token string) (WhoamiResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/v1/auth/whoami", nil)
	if err != nil {
		return WhoamiResponse{}, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return WhoamiResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return WhoamiResponse{}, fmt.Errorf("not logged in; run adversary login")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return WhoamiResponse{}, fmt.Errorf("whoami failed: %s", resp.Status)
	}
	var out WhoamiResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return WhoamiResponse{}, err
	}
	return out, nil
}

func (c Client) postJSON(ctx context.Context, path string, payload any, token string, out any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("request failed: %s", resp.Status)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

func PollInterval(login DeviceLogin) time.Duration {
	if login.Interval <= 0 {
		return 5 * time.Second
	}
	return time.Duration(login.Interval) * time.Second
}
