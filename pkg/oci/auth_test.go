package oci

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDockerCredentialHelper(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture")
	}
	home, bin := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	if err := os.MkdirAll(filepath.Join(home, ".docker"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".docker", "config.json"), []byte(`{"credHelpers":{"registry.example":"fixture"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(bin, "docker-credential-fixture")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nread server\n[ \"$server\" = registry.example ] || exit 1\nprintf '{\"Username\":\"user\",\"Secret\":\"secret\"}'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	got, ok := (DockerCredentialStore{}).Credentials("registry.example")
	if !ok || got.Username != "user" || got.Password != "secret" {
		t.Fatalf("got %#v, %v", got, ok)
	}
}

func TestDockerCredentialInputsAreBounded(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".docker"), 0700); err != nil {
		t.Fatal(err)
	}
	oversized := append([]byte(`{"auths":{"registry.example":{"auth":"dXNlcjpwYXNz"}}}`), bytes.Repeat([]byte(" "), (1<<20)+1)...)
	if err := os.WriteFile(filepath.Join(home, ".docker", "config.json"), oversized, 0600); err != nil {
		t.Fatal(err)
	}
	if _, ok := (DockerCredentialStore{}).Credentials("registry.example"); ok {
		t.Fatal("accepted oversized Docker config")
	}
}

func TestCredentialHelperOutputIsBounded(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture")
	}
	home, bin := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	if err := os.MkdirAll(filepath.Join(home, ".docker"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".docker", "config.json"), []byte(`{"credsStore":"overflow"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "docker-credential-overflow"), []byte("#!/bin/sh\nyes x\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, ok := (DockerCredentialStore{}).Credentials("registry.example"); ok {
		t.Fatal("accepted oversized helper output")
	}
}

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
	realm := "https://registry.example/v1/registry/token"

	_, err := readBearerToken(context.Background(), client, bearerChallenge{
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
		"missing token route",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("error %q missing %q", text, want)
		}
	}
	if strings.Contains(text, "scope=") || strings.Contains(text, "service=") {
		t.Fatalf("token query leaked: %s", text)
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
		Client:           client,
		Credentials:      staticCredentialStore{registry: "registry.example", creds: Credentials{Token: "adv_cli_token"}},
		Debug:            &debug,
		TokenAuthorities: map[string]TokenAuthority{"registry.example": {Origin: "https://auth.example", Service: "registry.example"}},
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

func TestUntrustedChallengeRealmReceivesNoStoredCredentials(t *testing.T) {
	var tokenAuthorization string
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Host {
		case "registry.example":
			if req.Header.Get("Authorization") == "Bearer anonymous-jwt" {
				return &http.Response{StatusCode: 200, Status: "200 OK", Body: io.NopCloser(strings.NewReader("ok")), Header: http.Header{}, Request: req}, nil
			}
			return &http.Response{StatusCode: 401, Status: "401 Unauthorized", Body: io.NopCloser(strings.NewReader("auth")), Header: http.Header{"Www-Authenticate": {`Bearer realm="https://evil.example/token",service="registry.example"`}}, Request: req}, nil
		case "evil.example":
			tokenAuthorization = req.Header.Get("Authorization")
			return &http.Response{StatusCode: 200, Status: "200 OK", Body: io.NopCloser(strings.NewReader(`{"token":"anonymous-jwt"}`)), Header: http.Header{}, Request: req}, nil
		default:
			t.Fatalf("unexpected host %s", req.URL.Host)
			return nil, nil
		}
	})}
	r := &HTTPRegistry{Client: client, Credentials: staticCredentialStore{registry: "registry.example", creds: Credentials{Username: "user", Password: "secret"}}}
	ref := Reference{Registry: "registry.example", Repository: "team/tool", Tag: "latest"}
	req, _ := r.newRequest(t.Context(), http.MethodGet, ref, "/manifests/latest", nil)
	resp, err := r.do(req, ref, "repository:team/tool:pull")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if tokenAuthorization != "" {
		t.Fatalf("stored credentials leaked to realm: %q", tokenAuthorization)
	}
}

func TestDockerHubTokenAuthority(t *testing.T) {
	r := NewHTTPRegistry()
	ref := Reference{Registry: "registry-1.docker.io", Repository: "library/alpine", Tag: "latest"}
	if !r.trustedTokenAuthority(ref, bearerChallenge{Realm: "https://auth.docker.io/token", Service: "registry.docker.io"}) {
		t.Fatal("Docker Hub authority not trusted")
	}
	if r.trustedTokenAuthority(ref, bearerChallenge{Realm: "https://evil.example/token", Service: "registry.docker.io"}) {
		t.Fatal("wrong Docker Hub origin trusted")
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
		Client:           client,
		Credentials:      staticCredentialStore{registry: "registry.example", creds: Credentials{Token: "adv_cli_token"}},
		Debug:            &debug,
		TokenAuthorities: map[string]TokenAuthority{"registry.example": {Origin: "https://auth.example", Service: "registry.example"}},
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
