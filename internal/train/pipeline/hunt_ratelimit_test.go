package pipeline

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/adversarylabs/adversary/internal/githubapi"
	"github.com/adversarylabs/adversary/internal/train/collect"
	"github.com/adversarylabs/adversary/internal/train/repos"
	"github.com/adversarylabs/adversary/internal/train/state"
)

func TestHistoricalHuntRetriesRateLimitedCollection(t *testing.T) {
	for _, endpoint := range []string{"", "/reviews", "/comments"} {
		t.Run("pull"+endpoint, func(t *testing.T) {
			githubapi.ResetRateGateForTest()
			t.Cleanup(githubapi.ResetRateGateForTest)
			var mu sync.Mutex
			attempts := 0
			var limitedAt time.Time
			var retriedAt time.Time
			client := githubapi.NewClient("test")
			client.HTTP = &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
				mu.Lock()
				defer mu.Unlock()
				status, body := http.StatusOK, `[]`
				header := make(http.Header)
				switch r.URL.Path {
				case "/repos/acme/api/pulls":
					body = `[{"number":42,"title":"candidate","merged_at":"2026-09-12T12:00:00Z","updated_at":"2026-09-12T12:00:00Z","user":{"login":"human"}}]`
				case "/repos/acme/api/pulls/42":
					body = `{"number":42,"title":"candidate","base":{"sha":"base"},"head":{"sha":"head"}}`
				}
				if r.URL.Path == "/repos/acme/api/pulls/42"+endpoint {
					attempts++
					if attempts == 1 {
						limitedAt = time.Now()
						status, body = http.StatusForbidden, `{"message":"secondary rate limit"}`
						header.Set("Retry-After", "1")
					} else {
						retriedAt = time.Now()
					}
				}
				return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body))}, nil
			})}
			collect.SetDefaultClient(client)
			t.Cleanup(func() { collect.SetDefaultClient(nil) })
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			root := t.TempDir()
			out := runParallelHunt(ctx, Options{AllHistory: true, AuthorSince: "2026-09-01", Concurrency: 1},
				[]repos.Repo{{Owner: "acme", Name: "api"}}, root, 10, 10, nil, nil, func(string, ...any) {}, nil)
			if out.interrupted != nil || out.blocked != nil {
				t.Fatalf("rate limit should recover: interrupted=%v blocked=%+v", out.interrupted, out.blocked)
			}
			mu.Lock()
			defer mu.Unlock()
			if attempts != 2 || retriedAt.Sub(limitedAt) < time.Second {
				t.Fatalf("attempts=%d retry delay=%s; want same endpoint retried after reset", attempts, retriedAt.Sub(limitedAt))
			}
			store, err := state.LoadDiscovery(root, "acme", "api")
			if err != nil {
				t.Fatal(err)
			}
			if got := store.PRs["42"].Outcome; got != state.OutcomeNoCases {
				t.Fatalf("final outcome=%s; want completed collection", got)
			}
		})
	}
}

func TestHistoricalHuntRateLimitWaitCanBeCanceled(t *testing.T) {
	githubapi.ResetRateGateForTest()
	t.Cleanup(githubapi.ResetRateGateForTest)
	client := githubapi.NewClient("test")
	client.HTTP = &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		status, body := http.StatusOK, `[{"number":42,"title":"candidate","merged_at":"2026-09-12T12:00:00Z","updated_at":"2026-09-12T12:00:00Z","user":{"login":"human"}}]`
		header := make(http.Header)
		if r.URL.Path != "/repos/acme/api/pulls" {
			status, body = http.StatusForbidden, `{"message":"secondary rate limit"}`
			header.Set("Retry-After", "3600")
		}
		return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	collect.SetDefaultClient(client)
	t.Cleanup(func() { collect.SetDefaultClient(nil) })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	progress := func(format string, args ...any) {
		if strings.Contains(fmt.Sprintf(format, args...), "waiting until") {
			cancel()
		}
	}
	out := runParallelHunt(ctx, Options{AllHistory: true, AuthorSince: "2026-09-01", Concurrency: 1},
		[]repos.Repo{{Owner: "acme", Name: "api"}}, t.TempDir(), 10, 10, nil, nil, progress, nil)
	if !errors.Is(out.interrupted, context.Canceled) {
		t.Fatalf("interrupted=%v; want canceled backoff", out.interrupted)
	}
}
