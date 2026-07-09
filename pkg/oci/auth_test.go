package oci

import (
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

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}
