package capsule

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/embedding"
	"github.com/bonjoski/coppermind/pkg/scratchpad"
	"github.com/bonjoski/coppermind/pkg/storage/sqlite"
)

func TestAdversarial_CartridgeV2SignedMergeDedupeAndAttacks(t *testing.T) {
	ctx := context.Background()
	tmp := t.TempDir()

	// 1. Setup source vault with 2 clean architectural memories
	srcStore, err := sqlite.NewSQLiteStore(filepath.Join(tmp, "src.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer srcStore.Close()
	srcMgr := brain.NewManager(srcStore, embedding.NewLocalHashEmbedder(128), scratchpad.NewMemoryScratchpad())
	defer srcMgr.Close()

	_, _ = srcMgr.Remember(ctx, brain.RememberRequest{
		SessionID:  "src",
		Category:   "architecture",
		Content:    "Fabrial routes benign linters to Airlock Tier 1 in <15ms.",
		Provenance: brain.ProvenanceLocalWorkspace,
		Metadata:   map[string]string{"git_repo": "fabrial"},
	})
	_, _ = srcMgr.Remember(ctx, brain.RememberRequest{
		SessionID:  "src",
		Category:   "architecture",
		Content:    "Aegisbox runs untrusted package managers in hardware microVMs.",
		Provenance: brain.ProvenanceLocalWorkspace,
		Metadata:   map[string]string{"git_repo": "aegisbox"},
	})

	kp, err := GenerateEd25519Keypair(filepath.Join(tmp, "keys"), false)
	if err != nil {
		t.Fatal(err)
	}

	signedPath := filepath.Join(tmp, "fabrial-arch.capsule")
	manifest, err := ExportCartridge(ctx, srcStore, signedPath, CartridgeExportOptions{
		Name:       "fabrial-arch",
		Repo:       "fabrial",
		PrivateKey: kp.PrivateKey,
	})
	if err != nil {
		t.Fatalf("ExportCartridge failed: %v", err)
	}
	if manifest.RecordCount != 1 {
		t.Fatalf("expected 1 filtered fabrial record, got %d", manifest.RecordCount)
	}

	// 2. Setup destination vault with its own pre-existing memory (must NOT be clobbered!)
	dstStore, err := sqlite.NewSQLiteStore(filepath.Join(tmp, "dst.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer dstStore.Close()
	dstMgr := brain.NewManager(dstStore, embedding.NewLocalHashEmbedder(128), scratchpad.NewMemoryScratchpad())
	defer dstMgr.Close()

	_, _ = dstMgr.Remember(ctx, brain.RememberRequest{
		SessionID:  "dst",
		Category:   "decision",
		Content:    "Pre-existing destination memory that must survive non-destructive merge.",
		Provenance: brain.ProvenanceLocalWorkspace,
	})

	// 3. Merge signed cartridge with verified public key
	res1, err := MergeCartridge(ctx, dstMgr, signedPath, CartridgeMergeOptions{RequiredPubKey: kp.PublicKey})
	if err != nil {
		t.Fatalf("MergeCartridge failed: %v", err)
	}
	if !res1.SignedVerified || res1.ImportedCount != 1 {
		t.Fatalf("unexpected merge result: %+v", res1)
	}

	// Re-merging identical cartridge MUST deduplicate to 0 new imports
	res2, err := MergeCartridge(ctx, dstMgr, signedPath, CartridgeMergeOptions{RequiredPubKey: kp.PublicKey})
	if err != nil || res2.ImportedCount != 0 || res2.DeduplicatedSkip != 1 {
		t.Fatalf("expected deduplicated re-merge, got %+v err=%v", res2, err)
	}

	// Verify destination memory survived intact
	cnt, _ := dstMgr.Count(ctx, "")
	if cnt != 2 {
		t.Fatalf("expected 2 total memories (1 existing + 1 merged), got %d", cnt)
	}

	// 4. Unsigned cartridge MUST fail closed unless --allow-unsigned is explicitly set
	unsignedPath := filepath.Join(tmp, "unsigned.capsule")
	_, err = ExportCartridge(ctx, srcStore, unsignedPath, CartridgeExportOptions{Name: "unsigned-pack"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := MergeCartridge(ctx, dstMgr, unsignedPath, CartridgeMergeOptions{}); !errors.Is(err, ErrCartridgeUnsigned) {
		t.Fatalf("expected ErrCartridgeUnsigned, got %v", err)
	}

	// 5. Tar symlink / path traversal attack MUST fail closed
	evilPath := filepath.Join(tmp, "evil_symlink.capsule")
	f, _ := os.Create(evilPath)
	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)
	_ = tw.WriteHeader(&tar.Header{
		Name:     "../../etc/passwd",
		Typeflag: tar.TypeSymlink,
		Linkname: "/etc/passwd",
	})
	_ = tw.Close()
	_ = gw.Close()
	_ = f.Close()

	if _, err := MergeCartridge(ctx, dstMgr, evilPath, CartridgeMergeOptions{AllowUnsigned: true}); !errors.Is(err, ErrCartridgeUnsafeArchive) {
		t.Fatalf("expected ErrCartridgeUnsafeArchive for tar symlink/traversal, got %v", err)
	}
}
