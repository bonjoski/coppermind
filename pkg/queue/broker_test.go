package queue

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestEmbeddedBroker_PublishAndSubscribe(t *testing.T) {
	ctx := context.Background()
	broker := NewEmbeddedBroker(64)
	defer broker.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	var receivedTasks []*TaskEnvelope
	var mu sync.Mutex

	err := broker.Subscribe(ctx, "tasks.reflection", func(_ context.Context, task *TaskEnvelope) error {
		mu.Lock()
		receivedTasks = append(receivedTasks, task)
		mu.Unlock()
		wg.Done()
		return nil
	})
	if err != nil {
		t.Fatalf("subscribe error: %v", err)
	}

	// Publish two tasks
	task1 := &TaskEnvelope{
		SessionID: "sess-1",
		Type:      TaskDeepReflect,
		Payload:   map[string]interface{}{"focus": "auth refactoring"},
	}
	task2 := &TaskEnvelope{
		SessionID: "sess-1",
		Type:      TaskSummarizeSession,
		Payload:   map[string]interface{}{"steps": 5},
	}

	if err := broker.Publish(ctx, "tasks.reflection", task1); err != nil {
		t.Fatalf("publish error: %v", err)
	}
	if err := broker.Publish(ctx, "tasks.reflection", task2); err != nil {
		t.Fatalf("publish error: %v", err)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// success
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for task handlers to fire")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(receivedTasks) != 2 {
		t.Fatalf("expected 2 received tasks, got %d", len(receivedTasks))
	}
	hasReflect := false
	hasSummarize := false
	for _, task := range receivedTasks {
		if task.Type == TaskDeepReflect {
			hasReflect = true
		}
		if task.Type == TaskSummarizeSession {
			hasSummarize = true
		}
	}
	if !hasReflect || !hasSummarize {
		t.Errorf("expected both TaskDeepReflect and TaskSummarizeSession, got: %v and %v", receivedTasks[0].Type, receivedTasks[1].Type)
	}
}

func TestEmbeddedBroker_TopicWildcards(t *testing.T) {
	ctx := context.Background()
	broker := NewEmbeddedBroker(64)
	defer broker.Close()

	var starCount, hashCount int
	var mu sync.Mutex

	// Subscribe with wildcard patterns
	_ = broker.Subscribe(ctx, "ingest.*", func(_ context.Context, task *TaskEnvelope) error {
		mu.Lock()
		starCount++
		mu.Unlock()
		return nil
	})
	_ = broker.Subscribe(ctx, "events.#", func(_ context.Context, task *TaskEnvelope) error {
		mu.Lock()
		hashCount++
		mu.Unlock()
		return nil
	})

	_ = broker.Publish(ctx, "ingest.code", &TaskEnvelope{ID: "t1"})
	_ = broker.Publish(ctx, "ingest.architecture", &TaskEnvelope{ID: "t2"})
	_ = broker.Publish(ctx, "ingest.sub.category", &TaskEnvelope{ID: "t3"})          // Should NOT match ingest.*
	_ = broker.Publish(ctx, "events.user.signup.confirmed", &TaskEnvelope{ID: "t4"}) // Should match events.#

	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if starCount != 2 {
		t.Errorf("expected 2 tasks for ingest.*, got %d", starCount)
	}
	if hashCount != 1 {
		t.Errorf("expected 1 task for events.#, got %d", hashCount)
	}
}
