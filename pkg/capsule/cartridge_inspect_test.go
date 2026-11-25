package capsule

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/bonjoski/coppermind/pkg/authz"
	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/embedding"
	"github.com/bonjoski/coppermind/pkg/scratchpad"
	"github.com/bonjoski/coppermind/pkg/storage/sqlite"
)

func TestInspectCartridge_SignedUnsignedAndAdversarialSymlink(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := sqlite.NewSQLiteStore(filepath.Join(dir, "src.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	mgr := brain.NewManager(store, embedding.NewLocalHashEmbedder(128), scratchpad.NewMemoryScratchpad())
	defer mgr.Close()

	_, err = mgr.Remember(ctx, brain.RememberRequest{
		SessionID:     "default",
		Category:      "architecture",
		Content:       "Fabrial routes Tier 1 through Airlock and Tier 2 through Aegisbox.",
		AuthorityTier: authz.TierName1Architecture,
		Metadata:      map[string]string{"git_repo": "fabrial"},
	})
	if err != nil {
		t.Fatal(err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)

	capPath := filepath.Join(dir, "fabrial.capsule")
	if _, err := ExportCartridge(ctx, store, capPath, CartridgeExportOptions{
		Name:       "fabrial-arch",
		Repo:       "fabrial",
		Tier:       authz.TierName1Architecture,
		PrivateKey: priv,
	}); err != nil {
		t.Fatal(err)
	}

	// 1. Valid inspect with pinned pubkey
	res, err := InspectCartridge(capPath, pub)
	if err != nil {
		t.Fatalf("InspectCartridge failed: %v", err)
	}
	if !res.MerkleValid || !res.Signed || !res.SignatureValid || len(res.SampleRecords) != 1 {
		t.Fatalf("unexpected inspect result: %+v", res)
	}

	// 2. Wrong pinned pubkey MUST fail closed
	if _, err := InspectCartridge(capPath, otherPub); !errors.Is(err, ErrCartridgeSignatureFailed) {
		t.Fatalf("expected ErrCartridgeSignatureFailed for mismatched pubkey, got %v", err)
	}

	// 3. Symlink path MUST fail closed
	symPath := filepath.Join(dir, "link.capsule")
	if err := os.Symlink(capPath, symPath); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectCartridge(symPath, pub); err == nil {
		t.Fatalf("SECURITY VIOLATION: symlink cartridge path was not refused")
	}
}
