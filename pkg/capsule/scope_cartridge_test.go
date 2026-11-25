package capsule

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"testing"

	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/embedding"
	"github.com/bonjoski/coppermind/pkg/scope"
	"github.com/bonjoski/coppermind/pkg/scratchpad"
	"github.com/bonjoski/coppermind/pkg/storage/sqlite"
)

func TestScopedCartridgeExportAndPrefixMerge(t *testing.T) {
	dir := t.TempDir()
	srcStore, err := sqlite.NewSQLiteStore(filepath.Join(dir, "src.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer srcStore.Close()

	ctx := context.Background()
	srcMgr := brain.NewManager(srcStore, embedding.NewLocalHashEmbedder(128), scratchpad.NewMemoryScratchpad())
	defer srcMgr.Close()

	for _, item := range []struct{ sc, content string }{
		{"platform", "Platform wide invariant"},
		{"platform/payments", "Payments idempotency invariant"},
		{"platform/payments/webhooks", "Stripe HMAC raw body verification"},
		{"platform/auth", "OIDC key rotation policy"},
	} {
		if _, err := srcMgr.Remember(ctx, brain.RememberRequest{
			Category:   "architecture",
			Scope:      item.sc,
			Content:    item.content,
			Provenance: brain.ProvenanceLocalWorkspace,
		}); err != nil {
			t.Fatal(err)
		}
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	outPath := filepath.Join(dir, "payments.capsule")
	manifest, err := ExportCartridge(ctx, srcStore, outPath, CartridgeExportOptions{
		Name:       "payments-pack",
		Scope:      "platform/payments",
		ScopeMode:  scope.ModeSubtree,
		PrivateKey: priv,
	})
	if err != nil {
		t.Fatalf("ExportCartridge failed: %v", err)
	}
	if manifest.RecordCount != 2 || manifest.FilterScope != "platform/payments" {
		t.Fatalf("expected 2 subtree records, got count=%d filterScope=%q", manifest.RecordCount, manifest.FilterScope)
	}

	// Merge into destination vault mounted beneath --scope-prefix "acme"
	dstStore, err := sqlite.NewSQLiteStore(filepath.Join(dir, "dst.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer dstStore.Close()
	dstMgr := brain.NewManager(dstStore, embedding.NewLocalHashEmbedder(128), scratchpad.NewMemoryScratchpad())
	defer dstMgr.Close()

	mergeRes, err := MergeCartridge(ctx, dstMgr, outPath, CartridgeMergeOptions{
		RequiredPubKey: pub,
		ScopePrefix:    "acme",
	})
	if err != nil {
		t.Fatalf("MergeCartridge failed: %v", err)
	}
	if mergeRes.ImportedCount != 2 {
		t.Fatalf("expected 2 imported records, got %d", mergeRes.ImportedCount)
	}

	scopes, err := dstStore.ListScopes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool)
	for _, s := range scopes {
		seen[s.Scope] = true
	}
	if !seen["acme/platform/payments"] || !seen["acme/platform/payments/webhooks"] {
		t.Fatalf("expected remapped scopes under acme/, got %+v", scopes)
	}

	// Adversarial: invalid scope prefix MUST fail closed
	if _, err := MergeCartridge(ctx, dstMgr, outPath, CartridgeMergeOptions{
		RequiredPubKey: pub,
		ScopePrefix:    "../escape",
	}); err == nil {
		t.Fatal("expected invalid ScopePrefix to fail closed")
	}
}
