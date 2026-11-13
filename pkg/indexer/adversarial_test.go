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

func TestADV_IndexerSecurity(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "coppermind-adv-index-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "coppermind.db")
	store, err := sqlite.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	defer store.Close()

	embedder := embedding.NewEmbedderFromEnv()
	sp := scratchpad.NewMemoryScratchpad()
	mgr := brain.NewManager(store, embedder, sp)

	// ADV-1: Path traversal / invalid path must fail safely
	_, err = IndexDirectory(context.Background(), mgr, filepath.Join(tempDir, "non_existent_subdir_12345"), IndexOptions{})
	if err == nil {
		t.Errorf("expected error indexing non-existent directory, got nil")
	}

	// ADV-2: Sensitive private key block in file must be skipped or rejected without persisting raw key
	subDir := filepath.Join(tempDir, "code")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatalf("failed to create code dir: %v", err)
	}

	privKeyFile := filepath.Join(subDir, "deploy_key.pem")
	privKeyContent := `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y1+abcdefghijklmnopqrstuvwxyz1234567890
-----END RSA PRIVATE KEY-----`
	if err := os.WriteFile(privKeyFile, []byte(privKeyContent), 0600); err != nil {
		t.Fatalf("failed to write pem file: %v", err)
	}

	stats, err := IndexDirectory(context.Background(), mgr, subDir, IndexOptions{})
	if err != nil {
		t.Fatalf("IndexDirectory returned unexpected error: %v", err)
	}

	if stats.FilesIndexed != 0 {
		t.Errorf("expected 0 files indexed when dir only contains private key pem, got %d", stats.FilesIndexed)
	}

	// ADV-3: Ensure private key was NOT inserted into database
	results, err := mgr.Recall(context.Background(), brain.RecallRequest{
		Query: "PRIVATE KEY",
	})
	if err != nil {
		t.Fatalf("Recall failed: %v", err)
	}
	if len(results) > 0 {
		t.Errorf("critical security failure: private key found in memory store: %v", results[0].Node.Content)
	}
}
