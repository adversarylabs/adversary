package modelreview

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

type camelTestTransport func(*http.Request) (*http.Response, error)

func (f camelTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func camelTestResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

const camelTestOK = `{"choices":[{"message":{"content":"{\"decision\":\"approve\"}"},"finish_reason":"stop"}]}`

var camelTestKeySequence atomic.Int64

func camelTestKey(t *testing.T) string {
	return t.Name() + strconv.FormatInt(camelTestKeySequence.Add(1), 10)
}

func TestCamelBusyRetriesExactRequestThroughSustainedCongestion(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		calls := 0
		var original string
		client := &http.Client{Transport: camelTestTransport(func(r *http.Request) (*http.Response, error) {
			body, _ := io.ReadAll(r.Body)
			calls++
			if calls == 1 {
				original = string(body)
			}
			if string(body) != original {
				t.Fatal("retry changed the request/prompt")
			}
			if calls <= 6 {
				return camelTestResponse(429, `{"error":{"message":"Cost pacing queue is full; retry later"}}`), nil
			}
			return camelTestResponse(200, camelTestOK), nil
		})}
		p := &CamelProvider{APIKey: camelTestKey(t), BaseURL: "http://test", ModelID: "auto", Client: client, RequestRetries: 8}
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		result, err := p.Review(ctx, validRequest)
		if err != nil || string(result.Output) != `{"decision":"approve"}` || calls != 7 {
			t.Fatalf("calls=%d result=%s err=%v", calls, result.Output, err)
		}
		if time.Since(start) < 2*time.Minute {
			t.Fatal("capacity backoff was too short")
		}
	})
}

func TestCamelBusyExhaustionAndAuthenticationAreDistinct(t *testing.T) {
	for _, status := range []int{401, 403, 429, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				calls := 0
				p := &CamelProvider{APIKey: camelTestKey(t), BaseURL: "http://test", ModelID: "auto", RequestRetries: 2,
					Client: &http.Client{Transport: camelTestTransport(func(*http.Request) (*http.Response, error) {
						calls++
						return camelTestResponse(status, `{"error":{"message":"Cost pacing queue is full; retry later"}}`), nil
					})}}
				_, err := p.Review(context.Background(), validRequest)
				var pe *ProviderError
				if !errors.As(err, &pe) || pe.StatusCode != status {
					t.Fatalf("error=%v", err)
				}
				if status == 401 || status == 403 {
					if calls != 1 || pe.Retryable || pe.Code == "camel_busy" {
						t.Fatalf("auth retried: calls=%d error=%v", calls, pe)
					}
				} else if calls != 3 || pe.Code != "camel_busy" || !pe.Retryable || !strings.Contains(pe.Message, "Camel capacity retry budget exhausted") {
					t.Fatalf("calls=%d error=%+v", calls, pe)
				}
			})
		})
	}
}

func TestCamelRetryAfterAndDeadline(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, raw := range []string{"120", now.Add(2 * time.Minute).Format(http.TimeFormat)} {
		if delay := camelRetryDelay(0, http.Header{"Retry-After": {raw}}, now); delay < 2*time.Minute {
			t.Fatalf("Retry-After %s shortened to %v", raw, delay)
		}
	}
	for i := 0; i < 10; i++ {
		d := camelRetryDelay(i, nil, now)
		if d < 2*time.Second || d > 75*time.Second {
			t.Fatalf("backoff=%v", d)
		}
	}
	if d := camelRetryDelay(0, http.Header{"Retry-After": {"18446744073709551615"}}, now); d <= 0 {
		t.Fatal("overflowed Retry-After")
	}
	synctest.Test(t, func(t *testing.T) {
		calls := 0
		p := &CamelProvider{APIKey: camelTestKey(t), BaseURL: "http://deadline", ModelID: "auto", RequestRetries: 8,
			Client: &http.Client{Transport: camelTestTransport(func(*http.Request) (*http.Response, error) {
				calls++
				r := camelTestResponse(429, `{}`)
				r.Header.Set("Retry-After", "3600")
				return r, nil
			})}}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_, err := p.Review(ctx, validRequest)
		if !errors.Is(err, context.DeadlineExceeded) || calls != 1 {
			t.Fatalf("calls=%d err=%v", calls, err)
		}
	})
}

func TestCamelConcurrencySharedAcrossProvidersAndModels(t *testing.T) {
	key := camelTestKey(t)
	var active, peak atomic.Int32
	entered := make(chan struct{}, 60)
	release := make(chan struct{})
	client := &http.Client{Transport: camelTestTransport(func(*http.Request) (*http.Response, error) {
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old; old = peak.Load() {
			if peak.CompareAndSwap(old, n) {
				break
			}
		}
		entered <- struct{}{}
		<-release
		return camelTestResponse(200, camelTestOK), nil
	})}
	var wg sync.WaitGroup
	for i := 0; i < 60; i++ {
		model := "model-a"
		if i%2 == 0 {
			model = "model-b"
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := &CamelProvider{APIKey: key, BaseURL: "http://concurrency", ModelID: model, Client: client, MaxConcurrency: 5}
			if _, err := p.Review(context.Background(), validRequest); err != nil {
				t.Error(err)
			}
		}()
	}
	for range 5 {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("admission stalled")
		}
	}
	close(release)
	wg.Wait()
	if peak.Load() != 5 {
		t.Fatalf("peak=%d want 5", peak.Load())
	}
}

func TestCamelGateCooldownAndCanceledWaiter(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		key := camelTestKey(t)
		g := sharedCamelGate("http://gate", key, 1)
		if err := g.acquire(context.Background()); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := g.acquire(ctx); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		g.cooldown(time.Minute)
		g.release()
		start := time.Now()
		if err := g.acquire(context.Background()); err != nil {
			t.Fatal(err)
		}
		if time.Since(start) < time.Minute {
			t.Fatal("another request bypassed shared cooldown")
		}
		g.release()
		if sharedCamelGate("http://gate/", key, 10) != g || g.limit != 1 {
			t.Fatal("separate broker bypassed credential limit")
		}
	})
}

func TestCamelCapacityRecoversGradually(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := sharedCamelGate("http://recovery", camelTestKey(t), 5)
		g.cooldown(time.Minute)
		if g.effective != 2 {
			t.Fatalf("congestion did not reduce cap: %d", g.effective)
		}
		for range 20 {
			g.success()
		}
		if g.effective != 2 {
			t.Fatal("in-flight responses prematurely restored cap")
		}
		time.Sleep(time.Minute)
		for range 10 {
			g.success()
		}
		if g.effective != 3 {
			t.Fatalf("expected gradual recovery, got %d", g.effective)
		}
		for range 100 {
			g.success()
		}
		if g.effective != 5 {
			t.Fatal("recovery exceeded reservation")
		}
		for range 10 {
			g.cooldown(time.Second)
		}
		if g.effective != 1 {
			t.Fatal("congestion eliminated all progress")
		}
	})
}

func TestCamelConfiguredConcurrencyValidation(t *testing.T) {
	for _, raw := range []string{"0", "257", "not-a-number", "3"} {
		lookup := func(name string) (string, bool) {
			switch name {
			case CamelKeyEnv:
				return t.Name(), true
			case CamelMaxConcurrencyEnv:
				return raw, true
			}
			return "", false
		}
		p, err := ProviderFromConfig(Config{Provider: "camel", Model: "auto"}, lookup, nil)
		if raw == "3" {
			if err != nil || p.(*CamelProvider).MaxConcurrency != 3 {
				t.Fatalf("configuration failed: %v", err)
			}
		} else if err == nil {
			t.Fatalf("accepted invalid cap %s", raw)
		}
	}
}
