package main

import (
	"sync"
	"time"
)

// ReplayCache enforces single use of challenge nonces and quote IDs. Entries
// outlive the longest valid quote, so nothing can be replayed while still fresh.
type ReplayCache struct {
	mu   sync.Mutex
	ttl  time.Duration
	seen map[string]time.Time
}

func NewReplayCache(ttl time.Duration) *ReplayCache {
	return &ReplayCache{ttl: ttl, seen: map[string]time.Time{}}
}

// Use returns false if the value was already used (a replay).
func (c *ReplayCache) Use(v string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if exp, ok := c.seen[v]; ok && now.Before(exp) {
		return false
	}
	if len(c.seen) > 10000 {
		for k, exp := range c.seen {
			if now.After(exp) {
				delete(c.seen, k)
			}
		}
	}
	c.seen[v] = now.Add(c.ttl)
	return true
}
