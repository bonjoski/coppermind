package brain

import (
	"context"
	"time"
)

// ValidatedScratchpad wraps any Scratchpad implementation (in-memory or Redis) with an
// in-process Stormcage-backed MemoryValidator, guaranteeing zero poisoned context enters
// working memory across multi-day autonomous agent sessions.
type ValidatedScratchpad struct {
	inner             Scratchpad
	validator         *MemoryValidator
	defaultSessionID  string
	defaultProvenance ProvenanceTier
}

// NewValidatedScratchpad wraps inner with Stormcage semantic taint validation on all Set writes.
// If inner is already a *ValidatedScratchpad, it is returned directly to avoid double-wrapping.
func NewValidatedScratchpad(inner Scratchpad, validator *MemoryValidator, sessionID string, defaultProvenance ProvenanceTier) *ValidatedScratchpad {
	if existing, ok := inner.(*ValidatedScratchpad); ok {
		return existing
	}
	if validator == nil {
		validator = NewMemoryValidator()
	}
	if sessionID == "" {
		sessionID = "default"
	}
	if defaultProvenance == "" {
		defaultProvenance = ProvenanceSharedDoc
	}
	return &ValidatedScratchpad{
		inner:             inner,
		validator:         validator,
		defaultSessionID:  sessionID,
		defaultProvenance: defaultProvenance,
	}
}

// Get delegates read lookups directly with zero overhead.
func (s *ValidatedScratchpad) Get(ctx context.Context, key string) (string, bool) {
	if s.inner == nil {
		return "", false
	}
	return s.inner.Get(ctx, key)
}

// Set validates and sanitizes val through the embedded Stormcage engine before writing.
func (s *ValidatedScratchpad) Set(ctx context.Context, key string, val string, ttl time.Duration) error {
	return s.SetWithProvenance(ctx, key, val, ttl, s.defaultProvenance)
}

// SetWithProvenance validates val with an explicit provenance taint classification before writing.
func (s *ValidatedScratchpad) SetWithProvenance(ctx context.Context, key string, val string, ttl time.Duration, provenance ProvenanceTier) error {
	verdict, err := s.validator.ValidateScratchpadWrite(ctx, s.defaultSessionID, key, val, provenance)
	if err != nil {
		return err
	}
	if s.inner == nil {
		return nil
	}
	return s.inner.Set(ctx, key, verdict.CleanedContent, ttl)
}

// Delete removes a key from the underlying scratchpad.
func (s *ValidatedScratchpad) Delete(ctx context.Context, key string) error {
	if s.inner == nil {
		return nil
	}
	return s.inner.Delete(ctx, key)
}

// AcquireLock delegates distributed/in-process locking to the underlying scratchpad.
func (s *ValidatedScratchpad) AcquireLock(ctx context.Context, lockName string, ttl time.Duration) (func(), error) {
	if s.inner == nil {
		return func() {}, nil
	}
	return s.inner.AcquireLock(ctx, lockName, ttl)
}

// Keys returns active non-expired keys from the underlying scratchpad.
func (s *ValidatedScratchpad) Keys(ctx context.Context) []string {
	if s.inner == nil {
		return nil
	}
	return s.inner.Keys(ctx)
}
