package scratchpad

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type item struct {
	value     string
	expiresAt time.Time
}

// MemoryScratchpad provides thread-safe in-memory working memory with TTL and distributed mutex simulation.
type MemoryScratchpad struct {
	mu    sync.RWMutex
	items map[string]item
	locks map[string]chan struct{}
}

// NewMemoryScratchpad instantiates a new in-memory scratchpad.
func NewMemoryScratchpad() *MemoryScratchpad {
	return &MemoryScratchpad{
		items: make(map[string]item),
		locks: make(map[string]chan struct{}),
	}
}

// Get retrieves a value from working memory. Returns false if missing or expired.
func (s *MemoryScratchpad) Get(_ context.Context, key string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	it, exists := s.items[key]
	if !exists {
		return "", false
	}
	if !it.expiresAt.IsZero() && time.Now().After(it.expiresAt) {
		return "", false
	}
	return it.value, true
}

// Set stores a key-value pair with an optional TTL duration.
func (s *MemoryScratchpad) Set(_ context.Context, key string, val string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var exp time.Time
	if ttl > 0 {
		exp = time.Now().Add(ttl)
	}

	s.items[key] = item{
		value:     val,
		expiresAt: exp,
	}
	return nil
}

// Delete removes a key from working memory.
func (s *MemoryScratchpad) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.items, key)
	return nil
}

// Keys returns all active non-expired keys.
func (s *MemoryScratchpad) Keys(_ context.Context) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()
	var active []string
	for k, it := range s.items {
		if it.expiresAt.IsZero() || now.Before(it.expiresAt) {
			active = append(active, k)
		}
	}
	return active
}

// AcquireLock attempts to acquire a named lock with a timeout/TTL.
func (s *MemoryScratchpad) AcquireLock(ctx context.Context, lockName string, ttl time.Duration) (func(), error) {
	s.mu.Lock()
	ch, exists := s.locks[lockName]
	if !exists {
		ch = make(chan struct{}, 1)
		s.locks[lockName] = ch
	}
	s.mu.Unlock()

	// Attempt to acquire lock token
	select {
	case ch <- struct{}{}:
		// Lock acquired!
		var once sync.Once
		unlock := func() {
			once.Do(func() {
				select {
				case <-ch:
				default:
				}
			})
		}

		// If TTL is specified, auto-release on timeout
		if ttl > 0 {
			go func() {
				select {
				case <-time.After(ttl):
					unlock()
				case <-ctx.Done():
					unlock()
				}
			}()
		}
		return unlock, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		return nil, fmt.Errorf("lock %q is currently held by another worker", lockName)
	}
}
