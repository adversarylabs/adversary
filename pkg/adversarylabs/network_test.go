package adversarylabs

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
			_, _ = w.Write([]byte(`{"results":[]}`))
		}
	}))
	defer server.Close()
	httpClient := newHTTPClientWithTimeout(20 * time.Millisecond)
	client := Client{BaseURL: server.URL, HTTP: httpClient}
	started := time.Now()
	_, err := client.Search(t.Context(), "query", "")
	elapsed := time.Since(started)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Search error = %v, want context deadline exceeded", err)
	}
	if httpClient.Timeout != 20*time.Millisecond {
		t.Fatalf("HTTP timeout = %s, want 20ms", httpClient.Timeout)
	}
	if elapsed >= time.Second {
		t.Fatalf("Search elapsed = %s, timeout was not enforced within the 1s test bound", elapsed)
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
