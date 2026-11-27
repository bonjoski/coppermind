package memguard

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
)

// HashKey computes a collision-free length-prefixed SHA-256 over taint, privilege,
// task intent, and content for sub-millisecond verdict caching.
func HashKey(taint string, privilege string, intent string, content string) string {
	h := sha256.New()
	writeLP := func(s string) {
		fmt.Fprintf(h, "%d:%s|", len(s), s)
	}
	writeLP(taint)
	writeLP(privilege)
	writeLP(intent)
	writeLP(content)
	return hex.EncodeToString(h.Sum(nil))
}

// VerdictCache provides a concurrency-safe, bounded memory cache for firewall verdicts
// using O(1) ring-buffer incremental eviction and deep copying to prevent data races.
type VerdictCache struct {
	mu      sync.RWMutex
	maxSize int
	entries map[string]*Verdict
	ring    []string
	cursor  int
}

// NewVerdictCache creates a bounded VerdictCache with capacity maxSize.
func NewVerdictCache(maxSize int) *VerdictCache {
	if maxSize <= 0 {
		maxSize = 2048
	}
	return &VerdictCache{
		maxSize: maxSize,
		entries: make(map[string]*Verdict, min(maxSize, 256)),
		ring:    make([]string, maxSize),
	}
}

// Get retrieves a deep-copied cached Verdict if present.
func (c *VerdictCache) Get(key string) (*Verdict, bool) {
	c.mu.RLock()
	v, ok := c.entries[key]
	if !ok {
		c.mu.RUnlock()
		return nil, false
	}
	cp := cloneVerdict(v)
	c.mu.RUnlock()
	cp.Cached = true
	return cp, true
}

// Set stores a deep-copied Verdict in the cache with O(1) incremental ring eviction.
func (c *VerdictCache) Set(key string, v *Verdict) {
	if v == nil {
		return
	}
	cp := cloneVerdict(v)
	cp.Cached = false

	c.mu.Lock()
	if _, exists := c.entries[key]; !exists {
		if oldKey := c.ring[c.cursor]; oldKey != "" {
			delete(c.entries, oldKey)
		}
		c.ring[c.cursor] = key
		c.cursor = (c.cursor + 1) % c.maxSize
	}
	c.entries[key] = cp
	c.mu.Unlock()
}

func cloneVerdict(v *Verdict) *Verdict {
	if v == nil {
		return nil
	}
	cp := *v
	if len(v.MatchedRules) > 0 {
		cp.MatchedRules = make([]string, len(v.MatchedRules))
		copy(cp.MatchedRules, v.MatchedRules)
	}
	if len(v.Details) > 0 {
		cp.Details = make([]string, len(v.Details))
		copy(cp.Details, v.Details)
	}
	return &cp
}
