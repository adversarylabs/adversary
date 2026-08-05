package collect

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RateLimitError means GitHub rejected the request for quota.
// Hunt should stop or wait rather than fan out more calls.
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
	var rl *RateLimitError
	return errors.As(err, &rl) || (err != nil && isRateLimitText(err.Error()))
}

var (
	rateMu        sync.Mutex
	rateHoldUntil time.Time
)

// waitForRateGate blocks if a previous rate-limit set a hold, until hold ends or ctx cancels.
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

// noteRateLimit records a global hold so other workers stop slamming the API.
func noteRateLimit(resetAt time.Time) {
	rateMu.Lock()
	defer rateMu.Unlock()
	if resetAt.IsZero() {
		// Default: pause 2 minutes when GitHub did not give a reset time.
		resetAt = time.Now().Add(2 * time.Minute)
	}
	// Cap wait at 1 hour so we do not sleep forever on bad clocks.
	if resetAt.After(time.Now().Add(time.Hour)) {
		resetAt = time.Now().Add(time.Hour)
	}
	if resetAt.After(rateHoldUntil) {
		rateHoldUntil = resetAt
	}
}

// parseRateLimit inspects gh stderr/stdout for rate-limit signals.
func parseRateLimit(out []byte) *RateLimitError {
	s := string(out)
	if !isRateLimitText(s) {
		return nil
	}
	rl := &RateLimitError{Message: softErr(s, 300)}
	// Try header-style reset unix timestamp (gh api -i or JSON body rarely has it).
	if m := regexp.MustCompile(`(?i)x-ratelimit-reset:\s*(\d+)`).FindSubmatch(out); len(m) == 2 {
		if sec, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
			rl.ResetAt = time.Unix(sec, 0)
		}
	}
	// "Reset at 2026-08-05 15:00:00 UTC" style (rare)
	if rl.ResetAt.IsZero() {
		if m := regexp.MustCompile(`(?i)resets?\s*(?:at|:)?\s*(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})`).FindStringSubmatch(s); len(m) == 2 {
			for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02T15:04:05"} {
				if t, err := time.Parse(layout, strings.ReplaceAll(m[1], " ", "T")); err == nil {
					rl.ResetAt = t
					break
				}
			}
		}
	}
	return rl
}

func isRateLimitText(s string) bool {
	l := strings.ToLower(s)
	return strings.Contains(l, "rate limit exceeded") ||
		strings.Contains(l, "api rate limit") ||
		strings.Contains(l, "secondary rate limit") ||
		strings.Contains(l, "abuse detection") ||
		(strings.Contains(l, "403") && strings.Contains(l, "rate limit"))
}

func softErr(s string, n int) string {
	s = strings.Join(strings.Fields(strings.ReplaceAll(s, "\n", " ")), " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// ghRun runs `gh` with cancelable context, shared rate-limit gate, and one retry after wait.
// args are passed to gh (e.g. "api", "repos/…", or "pr", "list", …).
func ghRun(ctx context.Context, args ...string) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := waitForRateGate(ctx); err != nil {
		return nil, fmt.Errorf("gh interrupted: %w", err)
	}
	out, err := exec.CommandContext(ctx, "gh", args...).CombinedOutput()
	if err == nil {
		return out, nil
	}
	if ctx.Err() != nil {
		return out, fmt.Errorf("gh interrupted: %w", ctx.Err())
	}
	if rl := parseRateLimit(out); rl != nil {
		noteRateLimit(rl.ResetAt)
		// Wait once for reset, then single retry.
		if err := waitForRateGate(ctx); err != nil {
			return out, rl
		}
		// Small jitter after hold so all workers don't stampede.
		select {
		case <-ctx.Done():
			return out, fmt.Errorf("gh interrupted: %w", ctx.Err())
		case <-time.After(500 * time.Millisecond):
		}
		out2, err2 := exec.CommandContext(ctx, "gh", args...).CombinedOutput()
		if err2 == nil {
			return out2, nil
		}
		if ctx.Err() != nil {
			return out2, fmt.Errorf("gh interrupted: %w", ctx.Err())
		}
		if rl2 := parseRateLimit(out2); rl2 != nil {
			noteRateLimit(rl2.ResetAt)
			return out2, rl2
		}
		return out2, fmt.Errorf("gh %s: %w (%s)", args[0], err2, softErr(string(out2), 300))
	}
	return out, fmt.Errorf("gh %s: %w (%s)", first(args), err, softErr(string(out), 300))
}

func first(args []string) string {
	if len(args) == 0 {
		return "gh"
	}
	return args[0]
}
