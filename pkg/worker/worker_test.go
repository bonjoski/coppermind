package worker

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/embedding"
	"github.com/bonjoski/coppermind/pkg/queue"
	"github.com/bonjoski/coppermind/pkg/router"
	"github.com/bonjoski/coppermind/pkg/scratchpad"
	"github.com/bonjoski/coppermind/pkg/storage/sqlite"
)

func TestCognitiveWorker_ReflectionPipeline(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "worker_test.db")

	store, err := sqlite.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to init store: %v", err)
	}
	defer store.Close()

	embedder := embedding.NewLocalHashEmbedder(128)
	sp := scratchpad.NewMemoryScratchpad()
	mgr := brain.NewManager(store, embedder, sp)

	broker := queue.NewEmbeddedBroker(32)
	defer broker.Close()

	rtr := router.NewLiteLLMRouter("http://127.0.0.1:54321/v1", "") // offline fallback

	cw := NewCognitiveWorker(broker, mgr, rtr)
	if err := cw.Start(ctx); err != nil {
		t.Fatalf("failed to start worker: %v", err)
	}
	defer cw.Stop()

	// Seed session with some episodic memories
	sessionID := "sess-worker-alpha"
	_, err = mgr.Remember(ctx, brain.RememberRequest{
		SessionID: sessionID,
		Category:  "architecture",
		Content:   "Always use Pure-Go SQLite in WAL mode with single-writer worker",
	})
	if err != nil {
		t.Fatalf("failed to store memory: %v", err)
	}

	_, err = mgr.Remember(ctx, brain.RememberRequest{
		SessionID: sessionID,
		Category:  "convention",
		Content:   "Sign all git commits with GPG key",
	})
	if err != nil {
		t.Fatalf("failed to store memory: %v", err)
	}

	// Dispatch background reflection task via broker
	task := &queue.TaskEnvelope{
		SessionID: sessionID,
		Type:      queue.TaskDeepReflect,
	}
	if err := broker.Publish(ctx, "tasks.reflection", task); err != nil {
		t.Fatalf("failed to publish task: %v", err)
	}

	// Allow worker goroutine to process
	var reflectionResults []*brain.SearchResult
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		reflectionResults, _ = mgr.Recall(ctx, brain.RecallRequest{
			SessionID: sessionID,
			Category:  "reflection",
			Query:     "reflection invariants",
			Limit:     1,
			MinScore:  0.0,
		})
		if len(reflectionResults) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if len(reflectionResults) == 0 {
		t.Fatalf("worker failed to synthesize and store reflection within deadline")
	}

	content := reflectionResults[0].Node.Content
	if !strings.Contains(content, "Autonomous Reflection") {
		t.Errorf("expected autonomous reflection header, got: %s", content)
	}
	if !strings.Contains(content, "Always use Pure-Go SQLite in WAL mode") {
		t.Errorf("expected synthesized invariant, got: %s", content)
	}

	metrics := cw.Metrics()
	if metrics.TasksProcessed != 1 {
		t.Errorf("expected 1 task processed, got %d", metrics.TasksProcessed)
	}

	// Test TaskExtractDecisions
	decTask := &queue.TaskEnvelope{
		SessionID: sessionID,
		Type:      queue.TaskExtractDecisions,
	}
	if err := broker.Publish(ctx, "tasks.decisions", decTask); err != nil {
		t.Fatalf("failed to publish decision task: %v", err)
	}

	var decResults []*brain.SearchResult
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		decResults, _ = mgr.Recall(ctx, brain.RecallRequest{
			SessionID: sessionID,
			Category:  "decision",
			Query:     "decision",
			Limit:     1,
			MinScore:  0.0,
		})
		if len(decResults) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(decResults) == 0 {
		t.Fatalf("worker failed to extract decisions within deadline")
	}

	// Test TaskDefragMemory
	defragTask := &queue.TaskEnvelope{
		SessionID: sessionID,
		Type:      queue.TaskDefragMemory,
	}
	if err := broker.Publish(ctx, "tasks.defrag", defragTask); err != nil {
		t.Fatalf("failed to publish defrag task: %v", err)
	}

	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if val, ok := sp.Get(ctx, "last_defrag_time"); ok && val != "" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if val, ok := sp.Get(ctx, "last_defrag_time"); !ok || val == "" {
		t.Fatalf("expected last_defrag_time to be populated by defrag task")
	}
}
