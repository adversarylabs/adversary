package oci

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestApplyAuthHeaderBearerToken(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://registry.example/v2/", nil)
	if err != nil {
		t.Fatal(err)
	}
	ApplyAuthHeader(req, Credentials{Token: "secret-token"})
	if got := req.Header.Get("Authorization"); got != "Bearer secret-token" {
		t.Fatalf("Authorization = %q", got)
	}
}

func TestApplyAuthHeaderBasic(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://registry.example/v2/", nil)
	if err != nil {
		t.Fatal(err)
	}
	ApplyAuthHeader(req, Credentials{Username: "user", Password: "pass"})
	username, password, ok := req.BasicAuth()
	if !ok || username != "user" || password != "pass" {
		t.Fatalf("basic auth = %q %q %v", username, password, ok)
	}
}

func TestReadBearerTokenErrorIncludesTokenURL(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Status:     "404 Not Found",
			Body:       io.NopCloser(strings.NewReader("missing token route")),
			Header:     http.Header{},
			Request:    req,
		}, nil
	})}
	realm := "http://registry.example/v1/registry/token"

	_, err := readBearerToken(client, bearerChallenge{
		Realm:   realm,
		Service: "adversary-registry",
	}, "repository:library/dockerfile-adversary:push,pull", Credentials{}, false)
	if err == nil {
		t.Fatal("expected error")
	}
	text := err.Error()
	for _, want := range []string{
		"token request failed: 404 Not Found",
		realm,
		"scope=repository%3Alibrary%2Fdockerfile-adversary%3Apush%2Cpull",
		"service=adversary-registry",
		"missing token route",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("error %q missing %q", text, want)
		}
	}
}

func TestHTTPRegistryDoesNotSendStoredBearerTokenToRegistry(t *testing.T) {
	var requests []string
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests = append(requests, req.URL.Host+req.URL.Path+" "+req.Header.Get("Authorization"))
		switch req.URL.Host {
		case "registry.example":
			if len(requests) == 1 {
				if got := req.Header.Get("Authorization"); got != "" {
					t.Fatalf("first registry request Authorization = %q, want empty", got)
				}
				return &http.Response{
					StatusCode: http.StatusUnauthorized,
					Status:     "401 Unauthorized",
					Body:       io.NopCloser(strings.NewReader("authentication required")),
					Header: http.Header{
						"Www-Authenticate": {`Bearer realm="https://auth.example/token",service="registry.example",scope="repository:marc/dockerfile-adversary:pull"`},
					},
					Request: req,
				}, nil
			}
			if got := req.Header.Get("Authorization"); got != "Bearer registry-jwt" {
				t.Fatalf("retry registry request Authorization = %q, want registry JWT", got)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Body:       io.NopCloser(strings.NewReader("ok")),
				Header:     http.Header{},
				Request:    req,
			}, nil
		case "auth.example":
			if got := req.Header.Get("Authorization"); got != "Bearer adv_cli_token" {
				t.Fatalf("token request Authorization = %q, want CLI token", got)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Body:       io.NopCloser(strings.NewReader(`{"token":"registry-jwt"}`)),
				Header:     http.Header{},
				Request:    req,
			}, nil
		default:
			t.Fatalf("unexpected request host %q", req.URL.Host)
			return nil, nil
		}
	})}
	var debug bytes.Buffer
	registry := &HTTPRegistry{
		Client:      client,
		Credentials: staticCredentialStore{registry: "registry.example", creds: Credentials{Token: "adv_cli_token"}},
		Debug:       &debug,
	}
	ref := Reference{Registry: "registry.example", Repository: "marc/dockerfile-adversary", Tag: "latest"}
	req, err := registry.newRequest(t.Context(), http.MethodGet, ref, "/manifests/latest", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := registry.do(req, ref, "repository:marc/dockerfile-adversary:pull")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %s, want 200 OK", resp.Status)
	}
	if len(requests) != 3 {
		t.Fatalf("requests = %v, want registry challenge, token, registry retry", requests)
	}
	debugText := debug.String()
	for _, want := range []string{
		"challenge realm=https://auth.example/token service=registry.example scope=repository:marc/dockerfile-adversary:pull",
		"retrying GET /v2/marc/dockerfile-adversary/manifests/latest authorization_header=true",
	} {
		if !strings.Contains(debugText, want) {
			t.Fatalf("debug output %q missing %q", debugText, want)
		}
	}
	for _, secret := range []string{"adv_cli_token", "registry-jwt"} {
		if strings.Contains(debugText, secret) {
			t.Fatalf("debug output leaked token %q: %s", secret, debugText)
		}
	}
}

func TestHTTPRegistryUsesRootChallengeWhenRepository401HasNoChallenge(t *testing.T) {
	var requests []string
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests = append(requests, req.Method+" "+req.URL.Host+req.URL.Path+" "+req.Header.Get("Authorization"))
		switch req.URL.Host {
		case "registry.example":
			switch req.URL.Path {
			case "/v2/marc/dockerfile-adversary/blobs/uploads/":
				if len(requests) == 1 {
					if got := req.Header.Get("Authorization"); got != "" {
						t.Fatalf("first registry request Authorization = %q, want empty", got)
					}
					return &http.Response{
						StatusCode: http.StatusUnauthorized,
						Status:     "401 Unauthorized",
						Body:       io.NopCloser(strings.NewReader("authentication required")),
						Header:     http.Header{},
						Request:    req,
					}, nil
				}
				if got := req.Header.Get("Authorization"); got != "Bearer registry-jwt" {
					t.Fatalf("retry registry request Authorization = %q, want registry JWT", got)
				}
				return &http.Response{
					StatusCode: http.StatusAccepted,
					Status:     "202 Accepted",
					Body:       io.NopCloser(strings.NewReader("accepted")),
					Header:     http.Header{},
					Request:    req,
				}, nil
			case "/v2/":
				return &http.Response{
					StatusCode: http.StatusUnauthorized,
					Status:     "401 Unauthorized",
					Body:       io.NopCloser(strings.NewReader("authentication required")),
					Header: http.Header{
						"Www-Authenticate": {`Bearer realm="https://auth.example/token",service="registry.example"`},
					},
					Request: req,
				}, nil
			default:
				t.Fatalf("unexpected registry path %q", req.URL.Path)
				return nil, nil
			}
		case "auth.example":
			if got := req.Header.Get("Authorization"); got != "Bearer adv_cli_token" {
				t.Fatalf("token request Authorization = %q, want CLI token", got)
			}
			if got := req.URL.Query().Get("scope"); got != "repository:marc/dockerfile-adversary:push,pull" {
				t.Fatalf("token request scope = %q, want requested scope", got)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Body:       io.NopCloser(strings.NewReader(`{"token":"registry-jwt"}`)),
				Header:     http.Header{},
				Request:    req,
			}, nil
		default:
			t.Fatalf("unexpected request host %q", req.URL.Host)
			return nil, nil
		}
	})}
	var debug bytes.Buffer
	registry := &HTTPRegistry{
		Client:      client,
		Credentials: staticCredentialStore{registry: "registry.example", creds: Credentials{Token: "adv_cli_token"}},
		Debug:       &debug,
	}
	ref := Reference{Registry: "registry.example", Repository: "marc/dockerfile-adversary", Tag: "latest"}
	req, err := registry.newRequest(t.Context(), http.MethodPost, ref, "/blobs/uploads/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := registry.do(req, ref, "repository:marc/dockerfile-adversary:push,pull")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %s, want 202 Accepted", resp.Status)
	}
	if len(requests) != 4 {
		t.Fatalf("requests = %v, want registry 401, root challenge, token, registry retry", requests)
	}
	debugText := debug.String()
	for _, want := range []string{
		"POST /v2/marc/dockerfile-adversary/blobs/uploads/ returned 401 without bearer challenge",
		"probing /v2/ for bearer challenge",
		"retrying POST /v2/marc/dockerfile-adversary/blobs/uploads/ authorization_header=true",
	} {
		if !strings.Contains(debugText, want) {
			t.Fatalf("debug output %q missing %q", debugText, want)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

type staticCredentialStore struct {
	registry string
	creds    Credentials
}

func (s staticCredentialStore) Credentials(registry string) (Credentials, bool) {
	if registry != s.registry {
		return Credentials{}, false
	}
	return s.creds, true
}
