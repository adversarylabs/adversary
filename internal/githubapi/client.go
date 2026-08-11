// Package githubapi is a thin direct HTTP client for GitHub REST and GraphQL.
// It does not shell out to gh.
package githubapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultRESTBase = "https://api.github.com"
	DefaultGQLURL   = "https://api.github.com/graphql"
	maxBodyBytes    = 32 << 20
	userAgent       = "adversary-cli"
	apiVersion      = "2022-11-28"
)

// Client talks to GitHub over HTTP.
type Client struct {
	HTTP     *http.Client
	RESTBase string
	GQLURL   string
	Token    string
	UA       string
}

// NewClient builds a client with defaults. Token may be empty for public reads.
func NewClient(token string) *Client {
	return &Client{
		HTTP:     &http.Client{Timeout: 60 * time.Second},
		RESTBase: DefaultRESTBase,
		GQLURL:   DefaultGQLURL,
		Token:    strings.TrimSpace(token),
		UA:       userAgent,
	}
}

// RESTGet performs GET restBase+path (path may be absolute under base, e.g. /repos/o/r/pulls/1).
func (c *Client) RESTGet(ctx context.Context, path string) ([]byte, http.Header, error) {
	return c.do(ctx, http.MethodGet, c.resolveREST(path), nil, true)
}

// RESTGetJSON decodes a single REST page into dest.
func (c *Client) RESTGetJSON(ctx context.Context, path string, dest any) error {
	body, _, err := c.RESTGet(ctx, path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, dest); err != nil {
		return fmt.Errorf("decode github response: %w", err)
	}
	return nil
}

// RESTGetPaginated follows Link rel=next and concatenates JSON array pages into one array.
func (c *Client) RESTGetPaginated(ctx context.Context, path string) ([]byte, error) {
	var pages []json.RawMessage
	next := c.resolveREST(path)
	for next != "" {
		if err := waitForRateGate(ctx); err != nil {
			return nil, err
		}
		body, hdr, err := c.doURL(ctx, http.MethodGet, next, nil, true)
		if err != nil {
			return nil, err
		}
		trim := bytes.TrimSpace(body)
		if len(trim) > 0 && trim[0] == '[' {
			var arr []json.RawMessage
			if err := json.Unmarshal(trim, &arr); err != nil {
				return nil, fmt.Errorf("decode github page: %w", err)
			}
			pages = append(pages, arr...)
		} else {
			// Single object endpoint — return as-is on first page.
			return body, nil
		}
		next = parseNextLink(hdr.Get("Link"))
	}
	if pages == nil {
		return []byte("[]"), nil
	}
	out, err := json.Marshal(pages)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GraphQL posts a GraphQL query/mutation.
func (c *Client) GraphQL(ctx context.Context, query string, variables map[string]any, dest any) error {
	if err := waitForRateGate(ctx); err != nil {
		return err
	}
	payload := map[string]any{"query": query}
	if variables != nil {
		payload["variables"] = variables
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	// Mutations: no post-response retry (do() with retryGET=false).
	body, _, err := c.doURL(ctx, http.MethodPost, c.gqlURL(), raw, false)
	if err != nil {
		return err
	}
	var envelope struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return fmt.Errorf("decode graphql: %w", err)
	}
	if len(envelope.Errors) > 0 {
		return fmt.Errorf("graphql: %s", envelope.Errors[0].Message)
	}
	if dest == nil {
		return nil
	}
	if len(envelope.Data) == 0 {
		return fmt.Errorf("graphql: empty data")
	}
	return json.Unmarshal(envelope.Data, dest)
}

func (c *Client) do(ctx context.Context, method, path string, body []byte, retryGET bool) ([]byte, http.Header, error) {
	if err := waitForRateGate(ctx); err != nil {
		return nil, nil, err
	}
	return c.doURL(ctx, method, c.resolveREST(path), body, retryGET)
}

func (c *Client) doURL(ctx context.Context, method, fullURL string, body []byte, retryGET bool) ([]byte, http.Header, error) {
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	var lastErr error
	attempts := 1
	if retryGET && (method == http.MethodGet || method == http.MethodHead) {
		attempts = 3
	}
	for i := 0; i < attempts; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			case <-time.After(time.Duration(i) * 200 * time.Millisecond):
			}
		}
		var rdr io.Reader
		if body != nil {
			rdr = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, fullURL, rdr)
		if err != nil {
			return nil, nil, err
		}
		c.setHeaders(req, body != nil)
		resp, err := httpClient.Do(req)
		if err != nil {
			lastErr = err
			if !retryGET {
				return nil, nil, err
			}
			continue
		}
		limited := io.LimitReader(resp.Body, maxBodyBytes+1)
		data, readErr := io.ReadAll(limited)
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, resp.Header, readErr
		}
		if int64(len(data)) > maxBodyBytes {
			return nil, resp.Header, fmt.Errorf("github response exceeds %d bytes", maxBodyBytes)
		}
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == 403 && isRateLimitBody(data) {
			rl := rateLimitFromHeaders(resp.Header, data)
			noteRateLimit(rl.ResetAt)
			lastErr = rl
			// Repeating the same request cannot clear a primary or secondary
			// rate limit. Return immediately so higher layers can use cached
			// evidence or record a resumable blocked result instead of sleeping
			// inside an otherwise retryable GET.
			return data, resp.Header, rl
		}
		if resp.StatusCode == 502 || resp.StatusCode == 503 || resp.StatusCode == 504 {
			lastErr = fmt.Errorf("github %s: HTTP %d", method, resp.StatusCode)
			if retryGET && i+1 < attempts {
				continue
			}
			return data, resp.Header, lastErr
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			msg := softErr(string(data), 300)
			if resp.StatusCode == 401 || resp.StatusCode == 403 {
				return data, resp.Header, &AuthError{Status: resp.StatusCode, Message: msg}
			}
			return data, resp.Header, fmt.Errorf("github %s %s: HTTP %d (%s)", method, fullURL, resp.StatusCode, msg)
		}
		return data, resp.Header, nil
	}
	if lastErr != nil {
		return nil, nil, lastErr
	}
	return nil, nil, fmt.Errorf("github request failed")
}

func (c *Client) setHeaders(req *http.Request, hasBody bool) {
	ua := c.UA
	if ua == "" {
		ua = userAgent
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", apiVersion)
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if hasBody {
		req.Header.Set("Content-Type", "application/json")
		// GraphQL prefers application/json Accept.
		if strings.Contains(req.URL.Path, "graphql") || strings.HasSuffix(req.URL.Path, "/graphql") {
			req.Header.Set("Accept", "application/json")
		}
	}
}

func (c *Client) resolveREST(path string) string {
	base := strings.TrimRight(c.RESTBase, "/")
	if base == "" {
		base = DefaultRESTBase
	}
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return base + path
}

func (c *Client) gqlURL() string {
	if strings.TrimSpace(c.GQLURL) != "" {
		return c.GQLURL
	}
	return DefaultGQLURL
}

func parseNextLink(link string) string {
	// Link: <url>; rel="next", <url>; rel="last"
	for _, part := range strings.Split(link, ",") {
		part = strings.TrimSpace(part)
		if !strings.Contains(part, `rel="next"`) && !strings.Contains(part, `rel=next`) {
			continue
		}
		if i := strings.Index(part, "<"); i >= 0 {
			if j := strings.Index(part[i:], ">"); j > 0 {
				return part[i+1 : i+j]
			}
		}
	}
	return ""
}

func softErr(s string, n int) string {
	s = strings.Join(strings.Fields(strings.ReplaceAll(s, "\n", " ")), " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// AuthError is a 401/403 from GitHub that is not a rate limit.
type AuthError struct {
	Status  int
	Message string
}

func (e *AuthError) Error() string {
	return fmt.Sprintf("github auth failed (HTTP %d): %s", e.Status, e.Message)
}

// JoinPath builds a REST path with escaped segments.
func JoinPath(parts ...string) string {
	var b strings.Builder
	for _, p := range parts {
		b.WriteByte('/')
		b.WriteString(url.PathEscape(p))
	}
	return b.String()
}

// Query encodes URL query values.
func Query(vals map[string]string) string {
	if len(vals) == 0 {
		return ""
	}
	q := url.Values{}
	for k, v := range vals {
		q.Set(k, v)
	}
	return "?" + q.Encode()
}

// ParseLinkPage is exported for tests.
func ParseLinkPage(link string) string { return parseNextLink(link) }

// HeaderInt reads an int header.
func HeaderInt(h http.Header, key string) int {
	v := h.Get(key)
	if v == "" {
		return 0
	}
	n, _ := strconv.Atoi(v)
	return n
}
