package githubapi

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RateLimitError means GitHub rejected the request for quota.
type RateLimitError struct {
	ResetAt time.Time
	Message string
}

func (e *RateLimitError) Error() string {
	if e == nil {
		return "github rate limit exceeded"
	}
	if !e.ResetAt.IsZero() {
		wait := time.Until(e.ResetAt).Round(time.Second)
		if wait < 0 {
			wait = 0
		}
		return fmt.Sprintf("github API rate limit exceeded (resets in %s, at %s UTC)",
			wait, e.ResetAt.UTC().Format("15:04:05"))
	}
	if e.Message != "" {
		return "github API rate limit exceeded: " + softErr(e.Message, 200)
	}
	return "github API rate limit exceeded"
}

// IsRateLimit reports whether err is a rate-limit failure.
func IsRateLimit(err error) bool {
	if err == nil {
		return false
	}
	if _, ok := err.(*RateLimitError); ok {
		return true
	}
	return isRateLimitText(err.Error())
}

var (
	rateMu        sync.Mutex
	rateHoldUntil time.Time
)

func waitForRateGate(ctx context.Context) error {
	rateMu.Lock()
	until := rateHoldUntil
	rateMu.Unlock()
	if until.IsZero() || time.Now().After(until) {
		return nil
	}
	wait := time.Until(until)
	if wait <= 0 {
		return nil
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func noteRateLimit(resetAt time.Time) {
	rateMu.Lock()
	defer rateMu.Unlock()
	if resetAt.IsZero() {
		resetAt = time.Now().Add(2 * time.Minute)
	}
	if resetAt.After(time.Now().Add(time.Hour)) {
		resetAt = time.Now().Add(time.Hour)
	}
	if resetAt.After(rateHoldUntil) {
		rateHoldUntil = resetAt
	}
}

// ActiveRateLimit reports the process-wide GitHub hold, if one is currently
// active. Callers with replayable local data can use this to avoid sleeping at
// the request gate.
func ActiveRateLimit() (time.Time, bool) {
	rateMu.Lock()
	defer rateMu.Unlock()
	if rateHoldUntil.IsZero() || !rateHoldUntil.After(time.Now()) {
		return time.Time{}, false
	}
	return rateHoldUntil, true
}

func rateLimitFromHeaders(h http.Header, body []byte) *RateLimitError {
	rl := &RateLimitError{Message: softErr(string(body), 300)}
	if reset := h.Get("X-RateLimit-Reset"); reset != "" {
		if sec, err := strconv.ParseInt(reset, 10, 64); err == nil {
			rl.ResetAt = time.Unix(sec, 0)
		}
	}
	if rl.ResetAt.IsZero() {
		if ra := h.Get("Retry-After"); ra != "" {
			if sec, err := strconv.Atoi(ra); err == nil {
				rl.ResetAt = time.Now().Add(time.Duration(sec) * time.Second)
			}
		}
	}
	return rl
}

func isRateLimitBody(body []byte) bool {
	return isRateLimitText(string(body))
}

func isRateLimitText(s string) bool {
	l := strings.ToLower(s)
	return strings.Contains(l, "rate limit exceeded") ||
		strings.Contains(l, "api rate limit") ||
		strings.Contains(l, "secondary rate limit") ||
		strings.Contains(l, "abuse detection") ||
		(strings.Contains(l, "403") && strings.Contains(l, "rate limit"))
}

// ResetRateGateForTest clears the process-wide hold (tests only).
func ResetRateGateForTest() {
	rateMu.Lock()
	rateHoldUntil = time.Time{}
	rateMu.Unlock()
}

var _ = regexp.MustCompile // keep import stable if unused in some builds
