package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/bonjoski/coppermind/pkg/brain"
)

func TestVectorFormattingAndParsing(t *testing.T) {
	vec := []float32{0.123456, -0.654321, 0.999999, 0.0}
	str := FormatVector(vec)
	if str != "[0.123456,-0.654321,0.999999,0.000000]" {
		t.Errorf("unexpected formatted vector: %s", str)
	}

	parsed, err := ParseVector(str)
	if err != nil {
		t.Fatalf("ParseVector failed: %v", err)
	}
	if len(parsed) != len(vec) {
		t.Fatalf("length mismatch: got %d, expected %d", len(parsed), len(vec))
	}
	for i := range vec {
		diff := parsed[i] - vec[i]
		if diff < -0.0001 || diff > 0.0001 {
			t.Errorf("mismatch at index %d: expected %f, got %f", i, vec[i], parsed[i])
		}
	}
}

func TestMerkleChainHashComputation(t *testing.T) {
	prev := ""
	h1 := ComputeNodeHash(prev, "node-1", "sess-1", "arch", "content 1", 1000)
	if len(h1) != 64 {
		t.Errorf("expected 64-char SHA256 hex string, got len %d", len(h1))
	}

	h2 := ComputeNodeHash(h1, "node-2", "sess-1", "arch", "content 2", 2000)
	if h2 == h1 {
		t.Errorf("chained hashes should differ")
	}
}

func TestPostgresStore_LiveIntegration(t *testing.T) {
	pgURL := os.Getenv("COPPERMIND_POSTGRES_URL")
	if pgURL == "" {
		t.Skip("Skipping live PostgreSQL integration test (COPPERMIND_POSTGRES_URL unset)")
	}

	ctx := context.Background()
	store, err := NewPostgresStore(ctx, Config{
		URL:       pgURL,
		Dimension: 128,
	})
	if err != nil {
		t.Fatalf("failed to connect to live postgres: %v", err)
	}
	defer store.Close()

	sessionID := "test-pg-sess"
	node := &brain.MemoryNode{
		ID:         "pg-node-1",
		SessionID:  sessionID,
		Category:   "architecture",
		Content:    "PostgreSQL 17 with pgvector cluster storage engine",
		Vector:     make([]float32, 128),
		Provenance: brain.ProvenanceLocalWorkspace,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	if err := store.Store(ctx, node); err != nil {
		t.Fatalf("failed to store node in postgres: %v", err)
	}

	count, err := store.Count(ctx, sessionID)
	if err != nil || count == 0 {
		t.Fatalf("failed to count nodes in postgres: %v (count: %d)", err, count)
	}

	_ = store.Delete(ctx, node.ID)
}
