package collect

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func eventsClient(t *testing.T, status int, body string, inspect func(*http.Request, string)) *http.Client {
	t.Helper()
	return &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		raw, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatalf("read query: %v", err)
		}
		if inspect != nil {
			inspect(req, string(raw))
		}
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
		}, nil
	})}
}

func TestDiscoverPRsFromGitHubEventsBatchesAndParses(t *testing.T) {
	client := eventsClient(t, http.StatusOK, strings.Join([]string{
		`{"repo_name":"acme/api","number":42,"title":"fix race"}`,
		`{"repo_name":"acme/api","number":41,"title":"validate input"}`,
		`{"repo_name":"other/tool","number":9,"title":"close leak"}`,
		"",
	}, "\n"), func(req *http.Request, query string) {
		if req.Method != http.MethodPost {
			t.Fatalf("method=%s", req.Method)
		}
		if req.URL.Scheme != "https" || req.URL.Query().Get("user") != "demo" {
			t.Fatalf("url=%s", req.URL)
		}
		for _, want := range []string{
			"PREWHERE repo_name IN ('acme/api', 'other/tool')",
			"created_at >= toDateTime('2025-08-18')",
			"action = 'merged'",
			"action = 'closed' AND merged = 1",
			"PullRequestReviewCommentEvent",
			"repo_rank <= 2",
			"FORMAT JSONEachRow",
			"timeout_overflow_mode = 'throw'",
		} {
			if !strings.Contains(query, want) {
				t.Fatalf("query missing %q:\n%s", want, query)
			}
		}
	})

	got, err := DiscoverPRsFromGitHubEvents([]string{"other/tool", "acme/api", "ACME/API"}, GitHubEventsOpts{
		Endpoint:     "https://mirror.example/query",
		PerRepoLimit: 2,
		Client:       client,
		Now:          func() time.Time { return time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got["acme/api"]) != 2 || got["acme/api"][0].Number != 42 || got["acme/api"][1].Number != 41 {
		t.Fatalf("acme results=%#v", got["acme/api"])
	}
	if got["other/tool"][0].URL != "https://github.com/other/tool/pull/9" {
		t.Fatalf("url=%q", got["other/tool"][0].URL)
	}
}

func TestDiscoverPRsFromGitHubEventsRejectsUnsafeInput(t *testing.T) {
	for _, repo := range []string{"missing-slash", "acme/a'b", "acme/x);DROP TABLE y", "https://github.com/acme/api"} {
		t.Run(repo, func(t *testing.T) {
			_, err := DiscoverPRsFromGitHubEvents([]string{repo}, GitHubEventsOpts{})
			if err == nil || !strings.Contains(err.Error(), "invalid GitHub repository") {
				t.Fatalf("err=%v", err)
			}
		})
	}
	for _, endpoint := range []string{"http://mirror.example", "https://user:secret@mirror.example", "not a url"} {
		t.Run(endpoint, func(t *testing.T) {
			_, err := DiscoverPRsFromGitHubEvents([]string{"acme/api"}, GitHubEventsOpts{Endpoint: endpoint})
			if err == nil {
				t.Fatal("expected endpoint error")
			}
		})
	}
	_, err := DiscoverPRsFromGitHubEvents([]string{"acme/api"}, GitHubEventsOpts{Since: "last week"})
	if err == nil || !strings.Contains(err.Error(), "YYYY-MM-DD") {
		t.Fatalf("since err=%v", err)
	}
	_, err = DiscoverPRsFromGitHubEvents([]string{"acme/api"}, GitHubEventsOpts{PerRepoLimit: maxEventsPerRepo + 1})
	if err == nil || !strings.Contains(err.Error(), "exceeds maximum") {
		t.Fatalf("limit err=%v", err)
	}
}

func TestDiscoverPRsFromGitHubEventsFailsClosedOnRemoteErrors(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{name: "http", status: http.StatusTooManyRequests, body: "quota exceeded", want: "HTTP 429"},
		{name: "malformed", status: http.StatusOK, body: "not-json\n", want: "parse github events row"},
		{name: "unrequested", status: http.StatusOK, body: `{"repo_name":"evil/repo","number":1}`, want: "unrequested repository"},
		{name: "bad-number", status: http.StatusOK, body: `{"repo_name":"acme/api","number":0}`, want: "invalid PR number"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DiscoverPRsFromGitHubEvents([]string{"acme/api"}, GitHubEventsOpts{
				Client: eventsClient(t, tc.status, tc.body, nil),
			})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err=%v want %q", err, tc.want)
			}
		})
	}
}

func TestDiscoverPRsFromGitHubEventsCancellationAndTransport(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := DiscoverPRsFromGitHubEvents([]string{"acme/api"}, GitHubEventsOpts{Context: ctx})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel err=%v", err)
	}

	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("offline")
	})}
	_, err = DiscoverPRsFromGitHubEvents([]string{"acme/api"}, GitHubEventsOpts{Client: client})
	if err == nil || !strings.Contains(err.Error(), "offline") {
		t.Fatalf("transport err=%v", err)
	}

	timeoutClient := &http.Client{
		Timeout: time.Millisecond,
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			<-req.Context().Done()
			return nil, req.Context().Err()
		}),
	}
	_, err = DiscoverPRsFromGitHubEvents([]string{"acme/api"}, GitHubEventsOpts{Client: timeoutClient})
	if err == nil || !strings.Contains(err.Error(), "deadline exceeded") {
		t.Fatalf("timeout err=%v", err)
	}
}

func TestDiscoverPRsFromGitHubEventsDeduplicatesRowsAndAcceptsEmpty(t *testing.T) {
	body := `{"repo_name":"acme/api","number":42,"title":"first"}` + "\n" +
		`{"repo_name":"ACME/API","number":42,"title":"duplicate"}` + "\n"
	got, err := DiscoverPRsFromGitHubEvents([]string{"acme/api"}, GitHubEventsOpts{
		Client: eventsClient(t, http.StatusOK, body, nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got["acme/api"]) != 1 || got["acme/api"][0].Title != "first" {
		t.Fatalf("got=%#v", got)
	}

	empty, err := DiscoverPRsFromGitHubEvents([]string{"acme/api"}, GitHubEventsOpts{
		Client: eventsClient(t, http.StatusOK, "", nil),
	})
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty=%#v err=%v", empty, err)
	}
}

func TestReadBoundedEventsResponseRejectsOversizeBody(t *testing.T) {
	_, err := readBoundedEventsResponse(strings.NewReader(strings.Repeat("x", maxEventsResponseBytes+1)))
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err=%v", err)
	}
}
