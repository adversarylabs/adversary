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

func TestBearerTokenCacheRejectsUnusableFetchedTokens(t *testing.T) {
	now := time.Date(2026, time.September, 16, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name  string
		entry bearerToken
	}{
		{name: "empty", entry: bearerToken{expiresAt: now.Add(time.Minute)}},
		{name: "already expired", entry: bearerToken{value: "token", expiresAt: now}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := NewBearerTokenCache()
			cache.now = func() time.Time { return now }

			token, err := cache.getOrFetch(context.Background(), "key", func() (bearerToken, error) {
				return tt.entry, nil
			})
			if err != errUnusableBearerToken {
				t.Fatalf("error = %v, want %v", err, errUnusableBearerToken)
			}
			if token != "" {
				t.Fatalf("token = %q, want empty", token)
			}
			if _, ok := cache.get("key"); ok {
				t.Fatal("unusable token was cached")
			}
		})
	}
}
