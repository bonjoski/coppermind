package seeder

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/embedding"
	"github.com/bonjoski/coppermind/pkg/scratchpad"
	"github.com/bonjoski/coppermind/pkg/storage/sqlite"
)

func TestSeeder_IngestFileAndDirectory(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "seeder_test.db")

	store, err := sqlite.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create sqlite store: %v", err)
	}
	defer store.Close()

	embedder := embedding.NewLocalHashEmbedder(128)
	sp := scratchpad.NewMemoryScratchpad()
	mgr := brain.NewManager(store, embedder, sp)

	// Create test markdown files
	doc1 := `---
title: "Test Invariants"
---

# Invariant Document

## Section 1: Security
Always use GPG key 7BB5B44244E586B0 for signed commits.

## Section 2: Concurrency
Never block SQLite readers when executing background writes.
`
	mdPath := filepath.Join(tmpDir, "invariants.md")
	if err := os.WriteFile(mdPath, []byte(doc1), 0644); err != nil {
		t.Fatalf("failed to write test md: %v", err)
	}

	count, err := IngestFile(ctx, mgr, mdPath, "test-cat")
	if err != nil {
		t.Fatalf("IngestFile returned error: %v", err)
	}

	if count != 2 {
		t.Errorf("expected 2 chunks, got %d", count)
	}

	// Verify semantic recall of ingested chunk
	results, err := mgr.Recall(ctx, brain.RecallRequest{
		Query: "Which GPG key is used for signed commits?",
	})
	if err != nil {
		t.Fatalf("Recall failed: %v", err)
	}

	if len(results) == 0 {
		t.Fatalf("expected search results, got 0")
	}

	if results[0].Node.Metadata["source_file"] != "invariants.md" {
		t.Errorf("expected source_file metadata 'invariants.md', got %q", results[0].Node.Metadata["source_file"])
	}

	// Test IngestFile with accepted-rfc category
	rfcDoc := `---
title: "RFC-2026-11-15-33"
---
# RFC-2026-11-15-33

## Architecture Baseline
PostgreSQL 17 with pgvector 0.8.0 is the official Profile B storage engine.
`
	rfcPath := filepath.Join(tmpDir, "plans", "accepted", "rfc-33.md")
	_ = os.MkdirAll(filepath.Dir(rfcPath), 0755)
	if err := os.WriteFile(rfcPath, []byte(rfcDoc), 0644); err != nil {
		t.Fatalf("failed to write rfc md: %v", err)
	}

	count, err = IngestFile(ctx, mgr, rfcPath, "accepted-rfc")
	if err != nil {
		t.Fatalf("IngestFile rfc returned error: %v", err)
	}
	if count == 0 {
		t.Fatalf("expected ingested rfc chunks")
	}

	rfcResults, err := mgr.Recall(ctx, brain.RecallRequest{
		Query: "Profile B storage engine",
	})
	if err != nil || len(rfcResults) == 0 {
		t.Fatalf("failed to recall rfc chunk: %v", err)
	}
	if rfcResults[0].Node.AuthorityTier != "TIER_1_ARCHITECTURE" {
		t.Errorf("expected TIER_1_ARCHITECTURE for accepted-rfc, got %s", rfcResults[0].Node.AuthorityTier)
	}
}
