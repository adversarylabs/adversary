package adversarylabs

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestValidateBaseURL(t *testing.T) {
	for _, bad := range []string{"http://api.example", "ftp://api.example", "https://user:pass@api.example", "https://api.example/#fragment", "https:///missing-host"} {
		if _, err := validateBaseURL(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	for _, good := range []string{"https://api.example", "http://localhost:8080", "http://127.0.0.1:8080"} {
		if _, err := validateBaseURL(good); err != nil {
			t.Errorf("rejected %q: %v", good, err)
		}
	}
}

func TestNewHTTPClientIsBounded(t *testing.T) {
	client := NewHTTPClient()
	if client == http.DefaultClient || client.Timeout != 2*time.Minute {
		t.Fatalf("client=%p default=%p timeout=%s", client, http.DefaultClient, client.Timeout)
	}
	if _, ok := client.Transport.(apiRetryTransport); !ok {
		t.Fatalf("transport = %T, want apiRetryTransport", client.Transport)
	}
}

func TestAPIClientTimeoutIsEnforced(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		_, _ = w.Write([]byte(`{"results":[]}`))
	}))
	defer server.Close()
	client := Client{BaseURL: server.URL, HTTP: newHTTPClientWithTimeout(20 * time.Millisecond)}
	if _, err := client.Search(t.Context(), "query", ""); err == nil || !strings.Contains(err.Error(), "Client.Timeout") {
		t.Fatalf("Search error = %v, want enforced client timeout", err)
	}
}

func TestAPIClientRedirectStripsCredentialsAcrossOrigin(t *testing.T) {
	var authorization, cookie string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization, cookie = r.Header.Get("Authorization"), r.Header.Get("Cookie")
		_, _ = w.Write([]byte(`{"results":[]}`))
	}))
	defer target.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/v1/search", http.StatusFound)
	}))
	defer origin.Close()

	client := NewHTTPClient()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, origin.URL+"/start", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("Cookie", "session=secret")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if authorization != "" || cookie != "" {
		t.Fatalf("cross-origin credentials leaked: authorization=%q cookie=%q", authorization, cookie)
	}
}

func FuzzValidateBaseURL(f *testing.F) {
	f.Add("https://api.example")
	f.Fuzz(func(t *testing.T, value string) { _, _ = validateBaseURL(value) })
}
