package oci

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestRegistryErrorParsesDistributionEnvelope(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://registry.example/v2/team/tool/manifests/latest", nil)
	resp := &http.Response{StatusCode: 429, Status: "429 Too Many Requests", Request: req, Body: io.NopCloser(strings.NewReader(`{"errors":[{"code":"TOOMANYREQUESTS","message":"slow down\u0000","detail":{"limit":1}}]}`))}
	err := registryError(resp)
	var typed *RegistryError
	if !errors.As(err, &typed) || len(typed.Codes) != 1 || typed.Codes[0].Code != "TOOMANYREQUESTS" || strings.Contains(err.Error(), "\x00") {
		t.Fatalf("error = %#v", err)
	}
}

type retryRoundTripper struct{ calls int }

func (r *retryRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	r.calls++
	status := http.StatusOK
	if r.calls < 3 {
		status = http.StatusTooManyRequests
	}
	return &http.Response{StatusCode: status, Status: http.StatusText(status), Header: http.Header{"Retry-After": {"0"}}, Body: io.NopCloser(http.NoBody), Request: req}, nil
}

func TestRetryTransportHonorsBoundedRateLimitRetry(t *testing.T) {
	base := &retryRoundTripper{}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://registry.example/v2/", nil)
	resp, err := (retryTransport{base: base}).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || base.calls != 3 {
		t.Fatalf("status=%d calls=%d", resp.StatusCode, base.calls)
	}
}

func TestSafeRedirectStripsCrossOriginAuthorization(t *testing.T) {
	previous := &http.Request{URL: mustURL(t, "https://registry.example/v2/x")}
	next := &http.Request{URL: mustURL(t, "https://auth.example/token"), Header: http.Header{"Authorization": {"Bearer secret"}, "Cookie": {"secret=1"}}}
	if err := safeRedirect(next, []*http.Request{previous}); err != nil {
		t.Fatal(err)
	}
	if next.Header.Get("Authorization") != "" || next.Header.Get("Cookie") != "" {
		t.Fatal("credentials crossed redirect origin")
	}
}

func TestSafeRedirectRejectsDowngrade(t *testing.T) {
	previous := &http.Request{URL: mustURL(t, "https://registry.example/v2/x")}
	next := &http.Request{URL: mustURL(t, "http://registry.example/v2/x")}
	if err := safeRedirect(next, []*http.Request{previous}); err == nil {
		t.Fatal("expected downgrade rejection")
	}
}

func TestValidatedUploadLocation(t *testing.T) {
	if _, err := validatedLocation("https", "registry.example", "https://evil.example/upload"); err == nil {
		t.Fatal("accepted cross-origin upload")
	}
	if _, err := validatedLocation("https", "registry.example", "http://registry.example/upload"); err == nil {
		t.Fatal("accepted insecure upload")
	}
	if got, err := validatedLocation("https", "registry.example", "/upload/1"); err != nil || got != "https://registry.example/upload/1" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestPlainHTTPRestrictedToLoopback(t *testing.T) {
	r := &HTTPRegistry{PlainHTTP: true}
	if _, err := r.newRequest(t.Context(), http.MethodGet, Reference{Registry: "registry.example", Repository: "x", Tag: "latest"}, "/manifests/latest", nil); err == nil {
		t.Fatal("accepted non-loopback HTTP")
	}
}

func TestBearerChallengeCaseAndQuotedComma(t *testing.T) {
	got, ok := parseBearerChallenge(`bEaReR realm="https://auth.example/token?a=b,c=d", SERVICE="registry.example", scope="repository:x:pull"`)
	if !ok || got.Realm != "https://auth.example/token?a=b,c=d" || got.Service != "registry.example" {
		t.Fatalf("got %#v, %v", got, ok)
	}
}

func FuzzBearerChallenge(f *testing.F) {
	f.Add(`Bearer realm="https://auth.example/token",service="registry.example"`)
	f.Fuzz(func(t *testing.T, value string) { _, _ = parseBearerChallenge(value) })
}

func mustURL(t *testing.T, value string) *url.URL {
	t.Helper()
	u, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
