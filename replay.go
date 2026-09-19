package main

import "sync"

// ReplayCache enforces single-use challenge nonces — the ANS-6 replay cache /
// DPoP jti defense. A replayed request reuses a nonce we have already seen.
type ReplayCache struct {
	mu   sync.Mutex
	seen map[string]bool
}

func NewReplayCache() *ReplayCache { return &ReplayCache{seen: map[string]bool{}} }

// Use returns false if the nonce was already used (i.e. this is a replay).
func (c *ReplayCache) Use(nonce string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen[nonce] {
		return false
	}
	c.seen[nonce] = true
	return true
}
