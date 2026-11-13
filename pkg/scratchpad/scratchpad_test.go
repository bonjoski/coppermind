package scratchpad

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestMemoryScratchpad_BasicAndTTL(t *testing.T) {
	ctx := context.Background()
	sp := NewMemoryScratchpad()

	// Set & Get
	err := sp.Set(ctx, "session:1:intent", "refactor auth logic", 0)
	if err != nil {
		t.Fatalf("unexpected set error: %v", err)
	}

	val, ok := sp.Get(ctx, "session:1:intent")
	if !ok || val != "refactor auth logic" {
		t.Fatalf("expected 'refactor auth logic', got %q (ok=%v)", val, ok)
	}

	// Short TTL
	err = sp.Set(ctx, "temp_key", "ephemeral", 50*time.Millisecond)
	if err != nil {
		t.Fatalf("unexpected set error: %v", err)
	}
	time.Sleep(75 * time.Millisecond)
	_, ok = sp.Get(ctx, "temp_key")
	if ok {
		t.Errorf("expected temp_key to expire after 50ms")
	}
}

func TestMemoryScratchpad_LockConcurrency(t *testing.T) {
	ctx := context.Background()
	sp := NewMemoryScratchpad()

	unlock1, err := sp.AcquireLock(ctx, "resource:git_worktree", 1*time.Second)
	if err != nil {
		t.Fatalf("failed to acquire first lock: %v", err)
	}

	// Second acquisition should fail while lock1 is held
	_, err = sp.AcquireLock(ctx, "resource:git_worktree", 1*time.Second)
	if err == nil {
		t.Fatalf("expected lock collision error, got nil")
	}

	// Release first lock
	unlock1()

	// Now second lock should succeed
	unlock2, err := sp.AcquireLock(ctx, "resource:git_worktree", 1*time.Second)
	if err != nil {
		t.Fatalf("failed to acquire lock after release: %v", err)
	}
	unlock2()
}

func TestMemoryScratchpad_ParallelAccess(t *testing.T) {
	ctx := context.Background()
	sp := NewMemoryScratchpad()

	var wg sync.WaitGroup
	workers := 10
	iterations := 100

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				key := "shared_key"
				_ = sp.Set(ctx, key, "some_value", 0)
				_, _ = sp.Get(ctx, key)
			}
		}(i)
	}

	wg.Wait()
}
