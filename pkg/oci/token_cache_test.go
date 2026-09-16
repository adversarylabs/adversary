package oci

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestBearerTokenCacheDoesNotRestoreInvalidatedInflightToken(t *testing.T) {
	cache := NewBearerTokenCache()
	started := make(chan struct{})
	release := make(chan struct{})
	var fetches atomic.Int32
	done := make(chan string, 1)
	go func() {
		token, err := cache.getOrFetch(context.Background(), "key", func() (bearerToken, error) {
			if fetches.Add(1) == 1 {
				close(started)
				<-release
				return bearerToken{value: "rejected", expiresAt: time.Now().Add(time.Minute)}, nil
			}
			return bearerToken{value: "fresh", expiresAt: time.Now().Add(time.Minute)}, nil
		})
		if err != nil {
			done <- "error: " + err.Error()
			return
		}
		done <- token
	}()

	<-started
	cache.invalidate("key")
	close(release)
	if got := <-done; got != "fresh" {
		t.Fatalf("token = %q, want fresh token", got)
	}
	if got := fetches.Load(); got != 2 {
		t.Fatalf("fetches = %d, want 2", got)
	}
	if got, ok := cache.get("key"); !ok || got != "fresh" {
		t.Fatalf("cached token = %q, %v; want fresh token", got, ok)
	}
}
