package capsule

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/embedding"
	"github.com/bonjoski/coppermind/pkg/scratchpad"
	"github.com/bonjoski/coppermind/pkg/storage/sqlite"
)

func TestCapsule_ExportAndImportWithSignature(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	srcDB := filepath.Join(tmpDir, "source.db")
	store, err := sqlite.NewSQLiteStore(srcDB)
	if err != nil {
		t.Fatalf("failed to init store: %v", err)
	}

	embedder := embedding.NewLocalHashEmbedder(128)
	sp := scratchpad.NewMemoryScratchpad()
	mgr := brain.NewManager(store, embedder, sp)

	// Ingest 5 records
	for i := 1; i <= 5; i++ {
		_, err := mgr.Remember(ctx, brain.RememberRequest{
			SessionID: "capsule_test",
			Category:  "architecture",
			Content:   "Capsule test invariant record",
		})
		if err != nil {
			t.Fatalf("failed to remember: %v", err)
		}
	}
	mgr.Close()

	// Generate Ed25519 keypair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key generation error: %v", err)
	}

	capsulePath := filepath.Join(tmpDir, "test.capsule")
	manifest, err := ExportCapsule(ctx, srcDB, capsulePath, privKey)
	if err != nil {
		t.Fatalf("ExportCapsule failed: %v", err)
	}

	if manifest.TotalRecords != 5 {
		t.Errorf("expected 5 records in manifest, got %d", manifest.TotalRecords)
	}
	if manifest.Signature == "" {
		t.Errorf("expected signature in manifest")
	}

	// Restore into target database
	targetDB := filepath.Join(tmpDir, "restored.db")
	importedManifest, err := ImportCapsule(ctx, capsulePath, targetDB, pubKey)
	if err != nil {
		t.Fatalf("ImportCapsule failed: %v", err)
	}

	if importedManifest.DBChecksum != manifest.DBChecksum {
		t.Errorf("checksum mismatch: %s vs %s", importedManifest.DBChecksum, manifest.DBChecksum)
	}

	// Verify restored database can be queried
	restoredStore, err := sqlite.NewSQLiteStore(targetDB)
	if err != nil {
		t.Fatalf("failed to open restored database: %v", err)
	}
	defer restoredStore.Close()

	count, err := restoredStore.Count(ctx, "")
	if err != nil {
		t.Fatalf("count error on restored db: %v", err)
	}
	if count != 5 {
		t.Errorf("expected 5 records in restored database, got %d", count)
	}
}

// TestADV_CapsulePathTraversalZipSlip verifies that malicious capsules containing
// ../ path traversal entries are strictly rejected.
func TestADV_CapsulePathTraversalZipSlip(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	maliciousCapsule := filepath.Join(tmpDir, "malicious.capsule")
	f, err := os.Create(maliciousCapsule)
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)

	// Attacker crafts malicious header attempting to escape sandbox directory
	evilHeader := &tar.Header{
		Name:     "../../../../etc/cron.d/malicious_payload",
		Mode:     0777,
		Size:     int64(len("malicious content")),
		ModTime:  time.Now(),
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(evilHeader); err != nil {
		t.Fatalf("failed to write header: %v", err)
	}
	if _, err := tw.Write([]byte("malicious content")); err != nil {
		t.Fatalf("failed to write body: %v", err)
	}
	_ = tw.Close()
	_ = gw.Close()

	targetDB := filepath.Join(tmpDir, "test.db")
	_, err = ImportCapsule(ctx, maliciousCapsule, targetDB, nil)
	if err == nil {
		t.Fatalf("ADV Failure: Malicious Zip-Slip path traversal was NOT rejected!")
	}
	if !strings.Contains(err.Error(), "illegal path traversal attempt") {
		t.Errorf("expected illegal path traversal error, got: %v", err)
	}
}

// TestADV_CapsuleTamperedChecksum verifies that modifying even 1 byte in the capsule database
// triggers a fail-closed integrity failure.
func TestADV_CapsuleTamperedChecksum(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	tamperedCapsule := filepath.Join(tmpDir, "tampered.capsule")
	f, err := os.Create(tamperedCapsule)
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)

	// Correct manifest with expected hash
	manifestContent := `{"version": "1.0", "total_records": 1, "db_checksum": "abcdef0123456789"}`
	_ = writeTarEntry(tw, "manifest.json", []byte(manifestContent))
	// Tampered database content with different hash
	_ = writeTarEntry(tw, "coppermind.db", []byte("tampered sqlite database bytes"))
	_ = tw.Close()
	_ = gw.Close()

	targetDB := filepath.Join(tmpDir, "tampered_target.db")
	_, err = ImportCapsule(ctx, tamperedCapsule, targetDB, nil)
	if err == nil {
		t.Fatalf("ADV Failure: Tampered capsule with invalid checksum was NOT rejected!")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Errorf("expected checksum mismatch error, got: %v", err)
	}
}
