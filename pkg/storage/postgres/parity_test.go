package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/bonjoski/coppermind/pkg/authz"
	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/embedding"
	"github.com/bonjoski/coppermind/pkg/graph"
	"github.com/bonjoski/coppermind/pkg/storage"
)

func TestPostgresStore_ProfileBParityInterfacesCompileAndHook(t *testing.T) {
	// Verify PostgresStore satisfies all 6 Profile A/B parity interfaces + Manager hooks.
	var s interface{} = &PostgresStore{}
	if _, ok := s.(storage.GraphStore); !ok {
		t.Fatal("PostgresStore does not implement storage.GraphStore")
	}
	if _, ok := s.(storage.IndexedFileStore); !ok {
		t.Fatal("PostgresStore does not implement storage.IndexedFileStore")
	}
	if _, ok := s.(storage.InboxStore); !ok {
		t.Fatal("PostgresStore does not implement storage.InboxStore")
	}
	if _, ok := s.(storage.VectorAdminStore); !ok {
		t.Fatal("PostgresStore does not implement storage.VectorAdminStore")
	}
	if _, ok := s.(storage.ExplorerStore); !ok {
		t.Fatal("PostgresStore does not implement storage.ExplorerStore")
	}
	if _, ok := s.(storage.CartridgeStore); !ok {
		t.Fatal("PostgresStore does not implement storage.CartridgeStore")
	}

	// Verify pre-write hook fails closed before hitting DB
	ps := &PostgresStore{}
	ps.SetPreWriteHook(func(ctx context.Context, node *brain.MemoryNode) error {
		return authz.ErrInvalidSupersession
	})
	if err := ps.Store(context.Background(), &brain.MemoryNode{ID: "probe-1", Content: "test"}); err != authz.ErrInvalidSupersession {
		t.Fatalf("expected pre-write hook to fail closed before DB access, got %v", err)
	}
}

func TestPostgresStore_LiveProfileBParityIntegration(t *testing.T) {
	pgURL := os.Getenv("COPPERMIND_POSTGRES_URL")
	if pgURL == "" {
		t.Skip("Skipping live Postgres Profile B parity test (COPPERMIND_POSTGRES_URL unset)")
	}
	ctx := context.Background()
	store, err := NewPostgresStore(ctx, Config{URL: pgURL, Dimension: 128})
	if err != nil {
		t.Fatalf("NewPostgresStore failed: %v", err)
	}
	defer store.Close()

	// 1. IndexedFileStore roundtrip
	repoKey := "test-parity-" + time.Now().Format("150405")
	if err := store.UpsertIndexedFile(ctx, storage.IndexedFileRecord{
		RepoRoot:      repoKey,
		RelPath:       "docs/adr-1.md",
		ContentSHA256: "abc123",
		ChunkIDs:      []string{"chunk_1"},
	}); err != nil {
		t.Fatalf("UpsertIndexedFile failed: %v", err)
	}
	files, err := store.ListIndexedFiles(ctx, repoKey)
	if err != nil || len(files) != 1 {
		t.Fatalf("ListIndexedFiles failed: %v %+v", err, files)
	}
	if err := store.PruneIndexedFile(ctx, repoKey, "docs/adr-1.md", nil); err != nil {
		t.Fatalf("PruneIndexedFile failed: %v", err)
	}

	// 2. InboxStore roundtrip
	tktID := "tkt_pg_" + time.Now().Format("150405")
	if err := store.EnqueuePendingTicket(ctx, storage.PendingLensTicket{
		ID:       tktID,
		LensName: "security-architect",
		MemoryID: "mem_pg_1",
		Summary:  "Parity check",
	}); err != nil {
		t.Fatalf("EnqueuePendingTicket failed: %v", err)
	}
	if err := store.ResolvePendingTicket(ctx, tktID, "dismissed"); err != nil {
		t.Fatalf("ResolvePendingTicket failed: %v", err)
	}

	// 3. GraphStore + VectorAdminStore
	if err := store.StoreEdges(ctx, []graph.Edge{{
		ID:           "edge_pg_" + time.Now().Format("150405"),
		SourceID:     "mem_pg_1",
		TargetEntity: "file:pkg/mcp/server.go",
		Relation:     graph.RelTouchesFile,
		Weight:       1.0,
	}}); err != nil {
		t.Fatalf("StoreEdges failed: %v", err)
	}
	if _, err := store.GetVectorCoverage(ctx, "local-hash-128"); err != nil {
		t.Fatalf("GetVectorCoverage failed: %v", err)
	}
	if _, err := store.ReindexVectors(ctx, embedding.NewLocalHashEmbedder(128), "local-hash-128", 32, true); err != nil {
		t.Fatalf("ReindexVectors dry-run failed: %v", err)
	}
}
