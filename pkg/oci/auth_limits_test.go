package oci

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBearerTokenResponseIsBounded(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat(" ", 1<<20) + `{"token":"secret"}`))
	}))
	defer s.Close()
	if _, err := readBearerToken(s.Client(), bearerChallenge{Realm: s.URL}, "", Credentials{}, false); err == nil {
		t.Fatal("accepted oversized whitespace token response")
	}
}
