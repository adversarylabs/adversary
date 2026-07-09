package oci

import (
	"net/http"
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
