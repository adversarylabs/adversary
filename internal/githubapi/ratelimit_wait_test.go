package githubapi

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestWaitForRateLimitIsInterruptible(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := WaitForRateLimit(ctx, &RateLimitError{ResetAt: time.Now().Add(time.Hour)})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v want context canceled", err)
	}
}
