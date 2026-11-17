package radar

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/bonjoski/coppermind/pkg/authz"
	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/capsule"
)

// FindCapsules discovers radar capsules across configured and default search directories.
func FindCapsules(cfg *RadarConfig) []string {
	var results []string
	seen := make(map[string]bool)

	addFile := func(path string) {
		clean := filepath.Clean(path)
		if strings.HasSuffix(clean, ".capsule") && !seen[clean] {
			if _, err := os.Stat(clean); err == nil {
				results = append(results, clean)
				seen[clean] = true
			}
		}
	}

	scanDir := func(dir string) {
		if dir == "" {
			return
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".capsule") {
				addFile(filepath.Join(dir, e.Name()))
			}
		}
	}

	if cfg != nil {
		if cfg.Settings.CapsulePath != "" {
			addFile(cfg.Settings.CapsulePath)
			return results
		}
		if cfg.Settings.CapsuleDir != "" {
			scanDir(cfg.Settings.CapsuleDir)
			return results
		}
		if cfg.Settings.DisableAmbientCapsules {
			return results
		}
	}

	// Project-local directory: .coppermind/capsules/
	scanDir(".coppermind/capsules")

	// User-global directory: ~/.coppermind/capsules/
	home, err := os.UserHomeDir()
	if err == nil {
		scanDir(filepath.Join(home, ".coppermind", "capsules"))
	}

	return results
}

// IngestCapsule extracts radar intelligence facts from a capsule archive and stores them in brain.Manager.
func IngestCapsule(ctx context.Context, capsulePath string, mgr *brain.Manager) (int, error) {
	inFile, err := os.Open(capsulePath)
	if err != nil {
		return 0, fmt.Errorf("failed to open capsule: %w", err)
	}
	defer inFile.Close()

	gr, err := gzip.NewReader(inFile)
	if err != nil {
		return 0, fmt.Errorf("invalid gzip capsule: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)

	var manifest *capsule.Manifest
	var dbBytes []byte

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, fmt.Errorf("error reading capsule tar: %w", err)
		}

		cleanName := filepath.Clean(hdr.Name)
		if strings.HasPrefix(cleanName, "..") || filepath.IsAbs(cleanName) {
			return 0, fmt.Errorf("security violation: path traversal in capsule (%s)", hdr.Name)
		}

		switch cleanName {
		case "manifest.json":
			data, err := io.ReadAll(tr)
			if err != nil {
				return 0, err
			}
			manifest = &capsule.Manifest{}
			if err := json.Unmarshal(data, manifest); err != nil {
				return 0, fmt.Errorf("invalid manifest JSON: %w", err)
			}
		case "coppermind.db":
			data, err := io.ReadAll(tr)
			if err != nil {
				return 0, err
			}
			dbBytes = data
		}
	}

	if manifest == nil {
		return 0, fmt.Errorf("missing manifest.json in capsule %s", capsulePath)
	}
	if len(dbBytes) == 0 {
		return 0, fmt.Errorf("empty coppermind.db in capsule %s", capsulePath)
	}

	// Verify database checksum integrity
	cksum := sha256.Sum256(dbBytes)
	if manifest.DBChecksum != "" && hex.EncodeToString(cksum[:]) != manifest.DBChecksum {
		return 0, fmt.Errorf("integrity violation: checksum mismatch for capsule %s", capsulePath)
	}

	// Write payload to temporary sqlite database
	tmpFile, err := os.CreateTemp("", "coppermind-capsule-*.db")
	if err != nil {
		return 0, fmt.Errorf("failed to create temp db: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := tmpFile.Write(dbBytes); err != nil {
		tmpFile.Close()
		return 0, err
	}
	tmpFile.Close()

	db, err := sql.Open("sqlite", tmpPath)
	if err != nil {
		return 0, fmt.Errorf("failed to open capsule database: %w", err)
	}
	defer db.Close()

	// Query for radar memories or all memories in capsule
	rows, err := db.QueryContext(ctx, `
		SELECT id, session_id, category, content, provenance, authority_tier, metadata_json
		FROM memory_nodes
		WHERE category = 'industry_radar' OR session_id LIKE 'radar-%'
	`)
	if err != nil {
		return 0, fmt.Errorf("failed to query capsule memories: %w", err)
	}
	defer rows.Close()

	ingested := 0

	for rows.Next() {
		var id, sessionID, category, content, provenance, authorityTier string
		var metaJSON sql.NullString

		if err := rows.Scan(&id, &sessionID, &category, &content, &provenance, &authorityTier, &metaJSON); err != nil {
			return ingested, err
		}

		meta := make(map[string]string)
		if metaJSON.Valid && metaJSON.String != "" && metaJSON.String != "null" {
			_ = json.Unmarshal([]byte(metaJSON.String), &meta)
		}
		if meta == nil {
			meta = make(map[string]string)
		}
		meta["imported_from_capsule"] = filepath.Base(capsulePath)

		if mgr != nil {
			req := brain.RememberRequest{
				SessionID:       sessionID,
				Category:        "industry_radar",
				Content:         content,
				Provenance:      brain.ProvenanceUntrustedWeb,
				AuthorityTier:   authz.TierName3Episodic,
				LifecycleStatus: string(authz.StatusActive),
				AuthorRole:      "radar-capsule-importer",
				Metadata:        meta,
				Deduplicate:     true,
			}
			if _, err := mgr.Remember(ctx, req); err == nil {
				ingested++
			}
		} else {
			ingested++
		}
	}

	// If no records matched category='industry_radar', fallback to reading all memory nodes
	if ingested == 0 {
		allRows, err := db.QueryContext(ctx, `
			SELECT id, session_id, category, content, provenance, authority_tier, metadata_json
			FROM memory_nodes
		`)
		if err == nil {
			defer allRows.Close()
			for allRows.Next() {
				var id, sessionID, category, content, provenance, authorityTier string
				var metaJSON sql.NullString
				if err := allRows.Scan(&id, &sessionID, &category, &content, &provenance, &authorityTier, &metaJSON); err == nil {
					meta := make(map[string]string)
					if metaJSON.Valid && metaJSON.String != "" && metaJSON.String != "null" {
						_ = json.Unmarshal([]byte(metaJSON.String), &meta)
					}
					if meta == nil {
						meta = make(map[string]string)
					}
					meta["imported_from_capsule"] = filepath.Base(capsulePath)
					if mgr != nil {
						req := brain.RememberRequest{
							SessionID:       sessionID,
							Category:        "industry_radar",
							Content:         content,
							Provenance:      brain.ProvenanceUntrustedWeb,
							AuthorityTier:   authz.TierName3Episodic,
							LifecycleStatus: string(authz.StatusActive),
							AuthorRole:      "radar-capsule-importer",
							Metadata:        meta,
							Deduplicate:     true,
						}
						if _, err := mgr.Remember(ctx, req); err == nil {
							ingested++
						}
					} else {
						ingested++
					}
				}
			}
		}
	}

	return ingested, nil
}
