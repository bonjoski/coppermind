package sqlite

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/embedding"
)

func TestSQLiteStore_SemanticAndEpisodic(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_coppermind.db")

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create sqlite store: %v", err)
	}
	defer store.Close()

	embedder := embedding.NewLocalHashEmbedder(128)

	// Ingest sample memories
	memories := []struct {
		id       string
		category string
		content  string
	}{
		{id: "m1", category: "architecture", content: "Always use Go 1.27 pure-Go SQLite with WAL mode"},
		{id: "m2", category: "architecture", content: "Use Touch ID biometric authorization via Locksmith"},
		{id: "m3", category: "convention", content: "All commits must be cryptographically signed with GPG"},
	}

	for _, m := range memories {
		vec, err := embedder.Embed(ctx, m.content)
		if err != nil {
			t.Fatalf("embed error: %v", err)
		}
		err = store.Store(ctx, &brain.MemoryNode{
			ID:         m.id,
			SessionID:  "sess-alpha",
			Category:   m.category,
			Content:    m.content,
			Vector:     vec,
			Provenance: brain.ProvenanceLocalWorkspace,
			CreatedAt:  time.Now(),
		})
		if err != nil {
			t.Fatalf("store error: %v", err)
		}
	}

	// Semantic recall test: query about SQLite
	query := "Which database and journal mode do we use in Go?"
	queryVec, err := embedder.Embed(ctx, query)
	if err != nil {
		t.Fatalf("embed query error: %v", err)
	}

	results, err := store.RecallSemantic(ctx, queryVec, brain.MemoryFilter{
		Limit: 2,
	})
	if err != nil {
		t.Fatalf("recall error: %v", err)
	}

	if len(results) == 0 {
		t.Fatalf("expected results, got 0")
	}

	if results[0].Node.ID != "m1" {
		t.Errorf("expected top result to be m1 (SQLite), got %s (content: %q, score: %f)",
			results[0].Node.ID, results[0].Node.Content, results[0].Score)
	}

	// Episodic recall test
	nodes, err := store.RecallEpisodic(ctx, "sess-alpha", 10)
	if err != nil {
		t.Fatalf("episodic recall error: %v", err)
	}
	if len(nodes) != 3 {
		t.Errorf("expected 3 episodic nodes, got %d", len(nodes))
	}
}

func TestSQLiteStore_ConcurrentWriters(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "concurrent_test.db")

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create sqlite store: %v", err)
	}
	defer store.Close()

	var wg sync.WaitGroup
	subagents := 8
	writesPerAgent := 25

	for a := 0; a < subagents; a++ {
		wg.Add(1)
		go func(agentID int) {
			defer wg.Done()
			for i := 0; i < writesPerAgent; i++ {
				nodeID := fmt.Sprintf("agent-%d-item-%d", agentID, i)
				node := &brain.MemoryNode{
					ID:         nodeID,
					SessionID:  fmt.Sprintf("subagent-%d", agentID),
					Category:   "concurrency_test",
					Content:    fmt.Sprintf("Concurrent memory block %d from subagent %d", i, agentID),
					Vector:     []float32{float32(agentID), float32(i)},
					Provenance: brain.ProvenanceLocalWorkspace,
				}
				if err := store.Store(ctx, node); err != nil {
					t.Errorf("agent %d failed write %d: %v", agentID, i, err)
					return
				}
			}
		}(a)
	}

	wg.Wait()

	total, err := store.Count(ctx, "subagent-")
	if err != nil {
		t.Fatalf("count error: %v", err)
	}

	expectedTotal := subagents * writesPerAgent
	if total != expectedTotal {
		t.Errorf("expected %d total records across parallel subagents, got %d", expectedTotal, total)
	}
}
