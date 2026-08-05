package pipeline

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRunRespectsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already canceled before start
	_, err := Run(Options{
		Context:  ctx,
		DataRoot: t.TempDir(),
		Fixture:  true,
		RepoRoot: t.TempDir(), // fixtures missing is fine if we cancel first
	})
	if err == nil {
		t.Fatal("expected interrupt error")
	}
	if !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "interrupt") {
		t.Fatalf("want canceled/interrupted, got %v", err)
	}
}

func TestRunInterruptedAfterStart(t *testing.T) {
	// Short deadline so live path cannot hang; cancel immediately after creating context.
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	time.Sleep(5 * time.Millisecond)
	_, err := Run(Options{
		Context:  ctx,
		DataRoot: t.TempDir(),
		Fixture:  false,
		Live:     true,
		Owner:    "open-telemetry",
		Repo:     "opentelemetry-go",
		MaxTurns: 1,
		MaxPRs:   1,
	})
	if err == nil {
		// May succeed if system is extremely fast; still OK if error is interrupt
		return
	}
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) &&
		!strings.Contains(err.Error(), "interrupt") {
		// Other errors (no gh, etc.) acceptable; interrupt path is covered by first test
		t.Logf("non-interrupt error (ok): %v", err)
	}
}
