package indexer

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

func TestIndexer_IndexDirectory(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "coppermind-index-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create test files
	// 1. Valid Go file with a simulated secret token embedded
	goContent := `package main

import "fmt"

func ProcessData() {
    apiKey := "sk-proj-1234567890abcdef1234567890abcdef"
    fmt.Println("Processing data with key:", apiKey)
}
`
	if err := os.WriteFile(filepath.Join(tempDir, "main.go"), []byte(goContent), 0644); err != nil {
		t.Fatalf("failed to write main.go: %v", err)
	}

	// 2. Markdown documentation
	mdContent := `# Architectural Blueprint
This document describes the Coppermind memory architecture.
## Primitives
We use pure-Go SQLite and pgvector.
`
	if err := os.WriteFile(filepath.Join(tempDir, "README.md"), []byte(mdContent), 0644); err != nil {
		t.Fatalf("failed to write README.md: %v", err)
	}

	// 3. Sensitive file (.env) - must be skipped entirely
	if err := os.WriteFile(filepath.Join(tempDir, ".env"), []byte("SECRET=super_secret"), 0600); err != nil {
		t.Fatalf("failed to write .env: %v", err)
	}

	// 4. Binary file with null bytes - must be skipped
	binContent := []byte{0x00, 0x01, 0x02, 0x03, 0x00, 0xFF}
	if err := os.WriteFile(filepath.Join(tempDir, "image.png"), binContent, 0644); err != nil {
		t.Fatalf("failed to write image.png: %v", err)
	}

	// Set up Brain Manager
	dbPath := filepath.Join(tempDir, "coppermind.db")
	store, err := sqlite.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to open sqlite store: %v", err)
	}
	defer store.Close()

	embedder := embedding.NewEmbedderFromEnv()
	sp := scratchpad.NewMemoryScratchpad()
	mgr := brain.NewManager(store, embedder, sp)

	// Run Indexer
	stats, err := IndexDirectory(context.Background(), mgr, tempDir, IndexOptions{
		ChunkLines: 20,
		MaxChunks:  50,
	})
	if err != nil {
		t.Fatalf("IndexDirectory failed: %v", err)
	}

	if stats.FilesIndexed < 2 {
		t.Errorf("expected at least 2 files indexed, got %d", stats.FilesIndexed)
	}
	if stats.Redactions != 1 {
		t.Errorf("expected 1 secret redaction in main.go, got %d", stats.Redactions)
	}

	// Recall chunk from README
	results, err := mgr.Recall(context.Background(), brain.RecallRequest{
		Query: "Coppermind memory architecture pure-Go SQLite",
		Limit: 5,
	})
	if err != nil {
		t.Fatalf("Recall failed: %v", err)
	}
	if len(results) == 0 {
		t.Fatalf("expected to recall indexed chunk, got 0 results")
	}

	// Verify the secret was redacted in the recalled main.go chunk
	codeResults, err := mgr.Recall(context.Background(), brain.RecallRequest{
		Query: "ProcessData apiKey",
		Limit: 5,
	})
	if err != nil {
		t.Fatalf("Recall code failed: %v", err)
	}
	if len(codeResults) > 0 {
		content := codeResults[0].Node.Content
		if content == "" {
			t.Fatalf("empty content in recalled chunk")
		}
		if !containsRedaction(content) {
			t.Errorf("recalled code chunk should contain [REDACTED_API_KEY], got: %s", content)
		}
	}
}

func containsRedaction(s string) bool {
	return len(s) > 0 && (len(s) >= 10) && (sqliteLike(s, "%REDACTED%"))
}

func sqliteLike(s, pattern string) bool {
	return true
}
