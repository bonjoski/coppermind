package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/bonjoski/coppermind/pkg/storage"
)

// IndexedFileRecord aliases the backend-agnostic incremental file manifest record.
type IndexedFileRecord = storage.IndexedFileRecord

// ListIndexedFiles loads the hash-incremental manifest for repoRoot.
func (s *SQLiteStore) ListIndexedFiles(ctx context.Context, repoRoot string) (map[string]IndexedFileRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT repo_root, rel_path, content_sha256, chunk_ids_json, indexed_at
		FROM indexed_files
		WHERE repo_root = ?
	`, repoRoot)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[string]IndexedFileRecord)
	for rows.Next() {
		var rec IndexedFileRecord
		var idsJSON string
		var indexedNano int64
		if err := rows.Scan(&rec.RepoRoot, &rec.RelPath, &rec.ContentSHA256, &idsJSON, &indexedNano); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(idsJSON), &rec.ChunkIDs)
		rec.IndexedAt = time.Unix(0, indexedNano)
		out[rec.RelPath] = rec
	}
	return out, rows.Err()
}

// UpsertIndexedFile records or updates a file's SHA-256 and active chunk IDs via the single-writer ring.
func (s *SQLiteStore) UpsertIndexedFile(ctx context.Context, rec IndexedFileRecord) error {
	if rec.IndexedAt.IsZero() {
		rec.IndexedAt = time.Now()
	}
	idsBytes, _ := json.Marshal(rec.ChunkIDs)
	return s.RunWriteTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.Exec(`
			INSERT INTO indexed_files (repo_root, rel_path, content_sha256, chunk_ids_json, indexed_at)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(repo_root, rel_path) DO UPDATE SET
				content_sha256=excluded.content_sha256,
				chunk_ids_json=excluded.chunk_ids_json,
				indexed_at=excluded.indexed_at
		`, rec.RepoRoot, rec.RelPath, rec.ContentSHA256, string(idsBytes), rec.IndexedAt.UnixNano())
		return err
	})
}

// DeleteIndexedChunks atomically deletes stale code chunks (and their FTS5/graph rows) via single-writer ring.
func (s *SQLiteStore) DeleteIndexedChunks(ctx context.Context, chunkIDs []string) error {
	if len(chunkIDs) == 0 {
		return nil
	}
	return s.RunWriteTx(ctx, func(tx *sql.Tx) error {
		for _, id := range chunkIDs {
			_, _ = tx.Exec("DELETE FROM memory_edges WHERE source_id = ? OR target_id = ?", id, id)
			_, _ = tx.Exec("DELETE FROM memory_fts WHERE id = ?", id)
			if _, err := tx.Exec("DELETE FROM memory_nodes WHERE id = ?", id); err != nil {
				return err
			}
		}
		return nil
	})
}

// PruneIndexedFile atomically deletes a removed file's chunks and manifest entry.
func (s *SQLiteStore) PruneIndexedFile(ctx context.Context, repoRoot, relPath string, chunkIDs []string) error {
	return s.RunWriteTx(ctx, func(tx *sql.Tx) error {
		for _, id := range chunkIDs {
			_, _ = tx.Exec("DELETE FROM memory_edges WHERE source_id = ? OR target_id = ?", id, id)
			_, _ = tx.Exec("DELETE FROM memory_fts WHERE id = ?", id)
			_, _ = tx.Exec("DELETE FROM memory_nodes WHERE id = ?", id)
		}
		_, err := tx.Exec("DELETE FROM indexed_files WHERE repo_root = ? AND rel_path = ?", repoRoot, relPath)
		return err
	})
}
