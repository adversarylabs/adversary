package oci

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const networkOperationTimeout = 2 * time.Minute

// NewHTTPClient returns the bounded client used for registry and token traffic.
// ProxyFromEnvironment intentionally preserves enterprise proxy/custom transport behavior.
func NewHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment, DialContext: dialer.DialContext,
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: time.Second, IdleConnTimeout: 90 * time.Second,
		MaxIdleConns: 32, MaxIdleConnsPerHost: 8,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}
	return &http.Client{Transport: retryTransport{base: transport}, Timeout: networkOperationTimeout, CheckRedirect: safeRedirect}
}

type retryTransport struct{ base http.RoundTripper }

func (t retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return t.base.RoundTrip(req)
	}
	var last *http.Response
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			delay := retryDelay(last, attempt)
			timer := time.NewTimer(delay)
			select {
			case <-req.Context().Done():
				timer.Stop()
				return nil, req.Context().Err()
			case <-timer.C:
			}
		}
		resp, err := t.base.RoundTrip(req)
		if err != nil {
			return nil, err
		}
		last = resp
		if resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode != http.StatusBadGateway && resp.StatusCode != http.StatusServiceUnavailable && resp.StatusCode != http.StatusGatewayTimeout {
			return resp, nil
		}
		if attempt < 2 {
			resp.Body.Close()
		}
	}
	return last, nil
}

func retryDelay(resp *http.Response, attempt int) time.Duration {
	if resp != nil {
		if seconds, err := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Retry-After"))); err == nil && seconds >= 0 {
			d := time.Duration(seconds) * time.Second
			if d > 10*time.Second {
				return 10 * time.Second
			}
			return d
		}
	}
	base := time.Duration(1<<uint(attempt-1)) * 100 * time.Millisecond
	return base + time.Duration(time.Now().UnixNano()%int64(base/2+1))
}

func safeRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("too many redirects")
	}
	if len(via) == 0 {
		return nil
	}
	previous := via[len(via)-1].URL
	if previous.Scheme == "https" && req.URL.Scheme != "https" {
		return errors.New("refusing HTTPS downgrade redirect")
	}
	if !sameOrigin(previous.Scheme, previous.Host, req.URL.Scheme, req.URL.Host) {
		req.Header.Del("Authorization")
		req.Header.Del("Cookie")
	}
	return nil
}

func sameOrigin(schemeA, hostA, schemeB, hostB string) bool {
	return strings.EqualFold(schemeA, schemeB) && strings.EqualFold(hostA, hostB)
}

func isLoopbackHost(hostport string) bool {
	host := hostport
	if parsed, _, err := net.SplitHostPort(hostport); err == nil {
		host = parsed
	}
	host = strings.Trim(host, "[]")
	return strings.EqualFold(host, "localhost") || net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()
}

type RegistryError struct {
	Operation, Registry, Repository string
	StatusCode                      int
	Status, Detail                  string
	Codes                           []RegistryErrorCode
}

type RegistryErrorCode struct{ Code, Message, Detail string }

func (e *RegistryError) Error() string {
	return fmt.Sprintf("OCI %s %s/%s failed: %s: %s", e.Operation, e.Registry, e.Repository, e.Status, e.Detail)
}

func withOperationDeadline(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, networkOperationTimeout)
}
