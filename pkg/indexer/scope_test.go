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

func TestIndexDirectory_ScopeFromConfig(t *testing.T) {
	tmp := t.TempDir()
	repoDir := filepath.Join(tmp, "monorepo")
	payDir := filepath.Join(repoDir, "services", "payments")
	authDir := filepath.Join(repoDir, "services", "auth")
	if err := os.MkdirAll(payDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(authDir, 0700); err != nil {
		t.Fatal(err)
	}

	cfg := `scope: platform
paths:
  services/payments: platform/payments
  services/auth: platform/auth
`
	if err := os.WriteFile(filepath.Join(repoDir, ".coppermind.yaml"), []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(payDir, "charge.go"), []byte("package payments\n// Charge handles idempotency keys\nfunc Charge() {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(authDir, "jwt.go"), []byte("package auth\n// VerifyJWKS rotates keys\nfunc VerifyJWKS() {}\n"), 0600); err != nil {
		t.Fatal(err)
	}

	store, err := sqlite.NewSQLiteStore(filepath.Join(tmp, "idx.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	mgr := brain.NewManager(store, embedding.NewLocalHashEmbedder(128), scratchpad.NewMemoryScratchpad())
	defer mgr.Close()

	ctx := context.Background()
	stats, err := IndexDirectory(ctx, mgr, repoDir, IndexOptions{
		ScopeFromConfig: true,
	})
	if err != nil {
		t.Fatalf("IndexDirectory failed: %v", err)
	}
	if stats.ChunksStored < 2 {
		t.Fatalf("expected >=2 indexed chunks, got %d", stats.ChunksStored)
	}

	scopes, err := store.ListScopes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool)
	for _, s := range scopes {
		seen[s.Scope] = true
	}
	if !seen["platform/payments"] || !seen["platform/auth"] {
		t.Fatalf("expected auto-scoped chunks under platform/payments and platform/auth, got %+v", scopes)
	}
}
