package oci

import (
	"context"
	"errors"
	"sync"
	"time"
)

var errUnusableBearerToken = errors.New("registry bearer token is empty or expires too soon")

// BearerTokenCache is an in-memory, concurrency-safe cache for registry bearer
// tokens. It is safe to share across HTTPRegistry instances created for one CLI
// invocation. Tokens and credential-derived keys are never persisted.
type BearerTokenCache struct {
	mu         sync.Mutex
	entries    map[string]bearerToken
	inflight   map[string]chan struct{}
	generation map[string]uint64
	now        func() time.Time
}

func NewBearerTokenCache() *BearerTokenCache {
	return &BearerTokenCache{
		entries:    make(map[string]bearerToken),
		inflight:   make(map[string]chan struct{}),
		generation: make(map[string]uint64),
		now:        time.Now,
	}
}

func (c *BearerTokenCache) get(key string) (string, bool) {
	if c == nil {
		return "", false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.initLocked()
	entry, ok := c.entries[key]
	if !ok || entry.value == "" || !c.now().Add(10*time.Second).Before(entry.expiresAt) {
		delete(c.entries, key)
		return "", false
	}
	return entry.value, true
}

func (c *BearerTokenCache) invalidate(key string) {
	if c == nil || key == "" {
		return
	}
	c.mu.Lock()
	c.initLocked()
	delete(c.entries, key)
	c.generation[key]++
	c.mu.Unlock()
}

func (c *BearerTokenCache) getOrFetch(ctx context.Context, key string, fetch func() (bearerToken, error)) (string, error) {
	if c == nil {
		entry, err := fetch()
		if err != nil {
			return "", err
		}
		if !usableBearerToken(entry, time.Now()) {
			return "", errUnusableBearerToken
		}
		return entry.value, nil
	}
	for {
		if token, ok := c.get(key); ok {
			return token, nil
		}
		c.mu.Lock()
		c.initLocked()
		if wait, ok := c.inflight[key]; ok {
			c.mu.Unlock()
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-wait:
				continue
			}
		}
		wait := make(chan struct{})
		c.inflight[key] = wait
		generation := c.generation[key]
		c.mu.Unlock()

		entry, err := fetch()
		c.mu.Lock()
		current := c.generation[key] == generation
		valid := err == nil && usableBearerToken(entry, c.now())
		if current && valid {
			c.entries[key] = entry
		}
		delete(c.inflight, key)
		close(wait)
		c.mu.Unlock()
		if err == nil && !current {
			continue
		}
		if err == nil && !valid {
			return "", errUnusableBearerToken
		}
		return entry.value, err
	}
}

func usableBearerToken(entry bearerToken, now time.Time) bool {
	return entry.value != "" && now.Add(10*time.Second).Before(entry.expiresAt)
}

func (c *BearerTokenCache) initLocked() {
	if c.entries == nil {
		c.entries = make(map[string]bearerToken)
	}
	if c.inflight == nil {
		c.inflight = make(map[string]chan struct{})
	}
	if c.generation == nil {
		c.generation = make(map[string]uint64)
	}
	if c.now == nil {
		c.now = time.Now
	}
}
