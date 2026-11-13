package capsule

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Manifest contains integrity and provenance metadata for a portable brain capsule.
type Manifest struct {
	Version      string    `json:"version"`
	ExportedAt   time.Time `json:"exported_at"`
	TotalRecords int       `json:"total_records"`
	DBChecksum   string    `json:"db_checksum"` // SHA-256 hex
	Signature    string    `json:"signature,omitempty"`
	PublicKey    string    `json:"public_key,omitempty"`
}

// ExportCapsule flushes the active SQLite database and packages it into a signed tar.gz capsule.
func ExportCapsule(ctx context.Context, dbPath, outputPath string, privKey ed25519.PrivateKey) (*Manifest, error) {
	if _, err := os.Stat(dbPath); err != nil {
		return nil, fmt.Errorf("source database not found: %w", err)
	}

	// 1. Create a pristine snapshot using VACUUM INTO to ensure WAL pages are consolidated
	tmpDir, err := os.MkdirTemp("", "coppermind-export-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	snapshotPath := filepath.Join(tmpDir, "snapshot.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open source database: %w", err)
	}
	// Flush and vacuum into snapshot
	_, err = db.ExecContext(ctx, fmt.Sprintf("VACUUM INTO '%s'", snapshotPath))
	if err != nil {
		db.Close()
		// Fallback: copy file if VACUUM INTO fails
		if copyErr := copyFile(dbPath, snapshotPath); copyErr != nil {
			return nil, fmt.Errorf("snapshot creation failed: %w", err)
		}
	} else {
		db.Close()
	}

	// Count total records in snapshot
	snapDB, err := sql.Open("sqlite", snapshotPath)
	totalRecords := 0
	if err == nil {
		_ = snapDB.QueryRow("SELECT COUNT(*) FROM memory_nodes").Scan(&totalRecords)
		snapDB.Close()
	}

	// 2. Compute SHA-256 checksum of the snapshot database
	snapshotData, err := os.ReadFile(snapshotPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read snapshot: %w", err)
	}
	checksumBytes := sha256.Sum256(snapshotData)
	checksumHex := hex.EncodeToString(checksumBytes[:])

	manifest := &Manifest{
		Version:      "1.0",
		ExportedAt:   time.Now().UTC(),
		TotalRecords: totalRecords,
		DBChecksum:   checksumHex,
	}

	// Sign manifest if private key is supplied
	if len(privKey) == ed25519.PrivateKeySize {
		sigPayload := []byte(fmt.Sprintf("%s:%s:%d", manifest.Version, manifest.DBChecksum, manifest.TotalRecords))
		sig := ed25519.Sign(privKey, sigPayload)
		manifest.Signature = hex.EncodeToString(sig)
		pub := privKey.Public().(ed25519.PublicKey)
		manifest.PublicKey = hex.EncodeToString(pub)
	}

	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}

	// 3. Package into tar.gz archive
	outFile, err := os.Create(outputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create capsule file: %w", err)
	}
	defer outFile.Close()

	gw := gzip.NewWriter(outFile)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	// Write manifest.json entry
	if err := writeTarEntry(tw, "manifest.json", manifestBytes); err != nil {
		return nil, err
	}

	// Write coppermind.db entry
	if err := writeTarEntry(tw, "coppermind.db", snapshotData); err != nil {
		return nil, err
	}

	return manifest, nil
}

// ImportCapsule verifies and restores a brain capsule into targetDBPath with strict path traversal defenses.
func ImportCapsule(_ context.Context, capsulePath, targetDBPath string, requiredPubKey ed25519.PublicKey) (*Manifest, error) {
	inFile, err := os.Open(capsulePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open capsule file: %w", err)
	}
	defer inFile.Close()

	gr, err := gzip.NewReader(inFile)
	if err != nil {
		return nil, fmt.Errorf("invalid or corrupted gzip capsule: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)

	var manifest *Manifest
	var dbBytes []byte

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("error reading capsule archive: %w", err)
		}

		// Zip Slip / Path Traversal Defense: enforce clean relative paths without .. or /
		cleanName := filepath.Clean(header.Name)
		if strings.HasPrefix(cleanName, "..") || filepath.IsAbs(cleanName) || strings.Contains(cleanName, string(filepath.Separator)+"..") {
			return nil, fmt.Errorf("security policy violation: illegal path traversal attempt in capsule (%s)", header.Name)
		}

		switch cleanName {
		case "manifest.json":
			data, err := io.ReadAll(tr)
			if err != nil {
				return nil, err
			}
			manifest = &Manifest{}
			if err := json.Unmarshal(data, manifest); err != nil {
				return nil, fmt.Errorf("corrupted manifest in capsule: %w", err)
			}
		case "coppermind.db":
			data, err := io.ReadAll(tr)
			if err != nil {
				return nil, err
			}
			dbBytes = data
		}
	}

	if manifest == nil {
		return nil, fmt.Errorf("invalid capsule: missing manifest.json")
	}
	if len(dbBytes) == 0 {
		return nil, fmt.Errorf("invalid capsule: missing coppermind.db payload")
	}

	// 1. Verify SHA-256 Checksum
	actualSum := sha256.Sum256(dbBytes)
	actualHex := hex.EncodeToString(actualSum[:])
	if actualHex != manifest.DBChecksum {
		return nil, fmt.Errorf("capsule integrity failure: checksum mismatch (expected %s, got %s)", manifest.DBChecksum, actualHex)
	}

	// 2. Verify Cryptographic Signature if required or present
	if len(requiredPubKey) == ed25519.PublicKeySize {
		if manifest.Signature == "" {
			return nil, fmt.Errorf("security policy violation: capsule is unsigned, but verified public key is required")
		}
		sigBytes, err := hex.DecodeString(manifest.Signature)
		if err != nil {
			return nil, fmt.Errorf("corrupted signature format: %w", err)
		}
		sigPayload := []byte(fmt.Sprintf("%s:%s:%d", manifest.Version, manifest.DBChecksum, manifest.TotalRecords))
		if !ed25519.Verify(requiredPubKey, sigPayload, sigBytes) {
			return nil, fmt.Errorf("security policy violation: cryptographic signature verification failed")
		}
	}

	// 3. Atomically restore into target database location
	targetDir := filepath.Dir(targetDBPath)
	_ = os.MkdirAll(targetDir, 0700)

	tmpTarget := targetDBPath + ".tmp"
	if err := os.WriteFile(tmpTarget, dbBytes, 0600); err != nil {
		return nil, fmt.Errorf("failed to write database: %w", err)
	}

	// Remove any existing WAL / SHM files to prevent state collision
	_ = os.Remove(targetDBPath + "-wal")
	_ = os.Remove(targetDBPath + "-shm")

	if err := os.Rename(tmpTarget, targetDBPath); err != nil {
		return nil, fmt.Errorf("failed to replace database: %w", err)
	}

	return manifest, nil
}

func writeTarEntry(tw *tar.Writer, name string, content []byte) error {
	header := &tar.Header{
		Name:     name,
		Mode:     0600,
		Size:     int64(len(content)),
		ModTime:  time.Now(),
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(header); err != nil {
		return err
	}
	_, err := tw.Write(content)
	return err
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}
