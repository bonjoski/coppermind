package watcher

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

func TestSyncVaultOnce_ScopeFromDirs(t *testing.T) {
	tmp := t.TempDir()
	vaultDir := filepath.Join(tmp, "notes")
	subDir := filepath.Join(vaultDir, "Payments", "Webhooks")
	if err := os.MkdirAll(subDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vaultDir, "overview.md"), []byte("# Platform Overview\nGeneral guidelines.\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "stripe.md"), []byte("# Stripe Webhooks\nAlways check raw body HMAC.\n"), 0600); err != nil {
		t.Fatal(err)
	}

	store, err := sqlite.NewSQLiteStore(filepath.Join(tmp, "watch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	mgr := brain.NewManager(store, embedding.NewLocalHashEmbedder(128), scratchpad.NewMemoryScratchpad())
	defer mgr.Close()

	ctx := context.Background()
	stats, err := SyncVaultOnce(ctx, mgr, vaultDir, Options{
		Scope:         "platform",
		ScopeFromDirs: true,
	})
	if err != nil {
		t.Fatalf("SyncVaultOnce failed: %v", err)
	}
	if stats.IndexedFiles != 2 {
		t.Fatalf("expected 2 indexed notes, got %d", stats.IndexedFiles)
	}

	scopes, err := store.ListScopes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool)
	for _, s := range scopes {
		seen[s.Scope] = true
	}
	if !seen["platform"] || !seen["platform/payments/webhooks"] {
		t.Fatalf("expected scopes platform and platform/payments/webhooks, got %+v", scopes)
	}
}
