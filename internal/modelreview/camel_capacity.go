package modelreview

import (
	"context"
	"crypto/sha256"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const defaultCamelConcurrency = 5

// All brokers created by one CLI process (including the verifier) share the
// credential's gate. Never key this by model or broker: composition creates a
// new broker per specialist. Credentials themselves are not stored in the map.
var camelGates = struct {
	sync.Mutex
	items map[[32]byte]*camelGate
}{items: make(map[[32]byte]*camelGate)}

type camelGate struct {
	mu                   sync.Mutex
	limit, active        int
	effective, successes int
	until                time.Time
	changed              chan struct{}
}

func sharedCamelGate(baseURL, key string, limit int) *camelGate {
	if limit <= 0 {
		limit = defaultCamelConcurrency
	}
	id := sha256.Sum256([]byte(strings.TrimRight(baseURL, "/") + "\x00" + key))
	camelGates.Lock()
	defer camelGates.Unlock()
	g := camelGates.items[id]
	if g == nil {
		g = &camelGate{limit: limit, effective: limit, changed: make(chan struct{})}
		camelGates.items[id] = g
	} else {
		g.mu.Lock()
		// Conflicting configurations may tighten, never bypass, an existing cap.
		g.limit = min(g.limit, limit)
		g.effective = min(g.effective, g.limit)
		g.mu.Unlock()
	}
	return g
}

func (g *camelGate) acquire(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		g.mu.Lock()
		delay := time.Until(g.until)
		if delay <= 0 && g.active < g.effective {
			g.active++
			g.mu.Unlock()
			return nil
		}
		changed := g.changed
		g.mu.Unlock()
		if delay > 0 {
			if err := waitForProviderRetry(ctx, delay); err != nil {
				return err
			}
		} else {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-changed:
			}
		}
	}
}

func (g *camelGate) release() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.active--
	close(g.changed)
	g.changed = make(chan struct{})
}

func (g *camelGate) cooldown(delay time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.effective = max(1, g.effective/2)
	g.successes = 0
	if until := time.Now().Add(delay); until.After(g.until) {
		g.until = until
	}
}

func (g *camelGate) success() {
	g.mu.Lock()
	defer g.mu.Unlock()
	// Responses from calls already in flight during a rejection are not
	// evidence of recovery. Restore slowly and never exceed the configured cap.
	if time.Now().Before(g.until) {
		return
	}
	g.successes++
	if g.successes >= 10 {
		g.effective = min(g.limit, g.effective+1)
		g.successes = 0
	}
}

// Retry-After is a minimum, not a hint to truncate to 30s. HTTP-date is valid
// too. The caller's original deadline bounds both admission and retry waiting.
func camelRetryDelay(attempt int, headers http.Header, now time.Time) time.Duration {
	delay := 2 * time.Second * time.Duration(1<<min(max(attempt, 0), 5))
	delay = min(delay, time.Minute)
	delay += time.Duration(rand.Int64N(int64(delay / 4)))
	raw := strings.TrimSpace(headers.Get("Retry-After"))
	if seconds, err := strconv.ParseUint(raw, 10, 64); err == nil {
		// Saturate to avoid overflow for malformed/unreasonably large values.
		const maxDelay = time.Duration(1<<63 - 1)
		if seconds > uint64(maxDelay/time.Second) {
			return maxDelay
		}
		return max(delay, time.Duration(seconds)*time.Second)
	}
	if when, err := http.ParseTime(raw); err == nil {
		return max(delay, when.Sub(now))
	}
	return delay
}
