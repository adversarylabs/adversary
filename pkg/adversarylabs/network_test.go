package adversarylabs

import (
	"context"
	"errors"
	"io"
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

func TestAPIRetryTransportUsesBoundedJitterAndClosesRetryBodies(t *testing.T) {
	var attempts int
	var bodies []*closeTrackingBody
	var jitterInputs, waits []time.Duration
	transport := apiRetryTransport{
		base: roundTripFunc(func(*http.Request) (*http.Response, error) {
			attempts++
			body := &closeTrackingBody{Reader: strings.NewReader("retry")}
			bodies = append(bodies, body)
			status := http.StatusServiceUnavailable
			if attempts == apiRetryAttempts {
				status = http.StatusOK
			}
			return &http.Response{StatusCode: status, Body: body, Header: make(http.Header)}, nil
		}),
		jitter: func(delay time.Duration) time.Duration {
			jitterInputs = append(jitterInputs, delay)
			return delay * 3 / 4
		},
		wait: func(_ context.Context, delay time.Duration) error {
			waits = append(waits, delay)
			return nil
		},
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://api.test/v1/search", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if attempts != apiRetryAttempts {
		t.Fatalf("attempts = %d, want %d", attempts, apiRetryAttempts)
	}
	if got, want := jitterInputs, []time.Duration{100 * time.Millisecond, 200 * time.Millisecond}; !equalDurations(got, want) {
		t.Fatalf("jitter inputs = %v, want %v", got, want)
	}
	if got, want := waits, []time.Duration{75 * time.Millisecond, 150 * time.Millisecond}; !equalDurations(got, want) {
		t.Fatalf("waits = %v, want %v", got, want)
	}
	if !bodies[0].closed || !bodies[1].closed || bodies[2].closed {
		t.Fatalf("body closed states = [%t %t %t]", bodies[0].closed, bodies[1].closed, bodies[2].closed)
	}
}

func TestAPIRetryTransportStopsAtAttemptLimit(t *testing.T) {
	var attempts, waits int
	transport := apiRetryTransport{
		base: roundTripFunc(func(*http.Request) (*http.Response, error) {
			attempts++
			return &http.Response{StatusCode: http.StatusBadGateway, Body: io.NopCloser(strings.NewReader("retry")), Header: make(http.Header)}, nil
		}),
		jitter: func(delay time.Duration) time.Duration { return delay / 2 },
		wait: func(context.Context, time.Duration) error {
			waits++
			return nil
		},
	}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodHead, "https://api.test/v1/search", nil)
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if attempts != apiRetryAttempts || waits != apiRetryAttempts-1 {
		t.Fatalf("attempts=%d waits=%d", attempts, waits)
	}
}

func TestAPIRetryAfterDelay(t *testing.T) {
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name  string
		value string
		want  time.Duration
		ok    bool
	}{
		{name: "delta seconds", value: "2", want: 2 * time.Second, ok: true},
		{name: "delta cap", value: "30", want: apiRetryAfterLimit, ok: true},
		{name: "delta overflow cap", value: "9223372036854775807", want: apiRetryAfterLimit, ok: true},
		{name: "zero", value: "0", want: 0, ok: true},
		{name: "HTTP date", value: now.Add(7 * time.Second).Format(http.TimeFormat), want: 7 * time.Second, ok: true},
		{name: "past HTTP date", value: now.Add(-time.Second).Format(http.TimeFormat), want: 0, ok: true},
		{name: "date cap", value: now.Add(time.Minute).Format(http.TimeFormat), want: apiRetryAfterLimit, ok: true},
		{name: "negative", value: "-1"},
		{name: "invalid", value: "later"},
		{name: "empty"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := apiRetryAfterDelay(tc.value, now)
			if got != tc.want || ok != tc.ok {
				t.Fatalf("apiRetryAfterDelay(%q) = (%s, %t), want (%s, %t)", tc.value, got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestAPIRetryAfterBypassesJitter(t *testing.T) {
	transport := apiRetryTransport{
		now: func() time.Time { return time.Unix(0, 0) },
		jitter: func(time.Duration) time.Duration {
			t.Fatal("jitter called for Retry-After")
			return 0
		},
	}
	if got := transport.retryDelay(0, "30"); got != apiRetryAfterLimit {
		t.Fatalf("retry delay = %s, want %s", got, apiRetryAfterLimit)
	}
}

func TestBoundedAPIRetryJitterStaysInUpperHalf(t *testing.T) {
	const delay = 200 * time.Millisecond
	for i := 0; i < 100; i++ {
		if got := boundedAPIRetryJitter(delay); got < delay/2 || got > delay {
			t.Fatalf("jitter = %s, want [%s, %s]", got, delay/2, delay)
		}
	}
}

func TestAPIRetryTransportDoesNotRetryMutation(t *testing.T) {
	var attempts int
	transport := apiRetryTransport{
		base: roundTripFunc(func(*http.Request) (*http.Response, error) {
			attempts++
			return &http.Response{StatusCode: http.StatusServiceUnavailable, Body: io.NopCloser(strings.NewReader("failed")), Header: make(http.Header)}, nil
		}),
		wait: func(context.Context, time.Duration) error {
			t.Fatal("wait called for POST")
			return nil
		},
	}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://api.test/v1/auth/login", strings.NewReader("{}"))
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1", attempts)
	}
}

func TestAPIRetryTransportCancellationClosesBody(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	body := &closeTrackingBody{Reader: strings.NewReader("retry")}
	transport := apiRetryTransport{
		base: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusTooManyRequests, Body: body, Header: make(http.Header)}, nil
		}),
		jitter: func(delay time.Duration) time.Duration { return delay / 2 },
		wait:   waitForAPIRetry,
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.test/v1/search", nil)
	resp, err := transport.RoundTrip(req)
	if resp != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("response=%v error=%v, want context cancellation", resp, err)
	}
	if !body.closed {
		t.Fatal("retry response body was not closed before cancellation")
	}
}

type closeTrackingBody struct {
	io.Reader
	closed bool
}

func (b *closeTrackingBody) Close() error {
	b.closed = true
	return nil
}

func equalDurations(a, b []time.Duration) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func FuzzValidateBaseURL(f *testing.F) {
	f.Add("https://api.example")
	f.Fuzz(func(t *testing.T, value string) { _, _ = validateBaseURL(value) })
}
