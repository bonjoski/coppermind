package sqlite

import (
	"context"
	"database/sql"
	"strings"

	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/scope"
	"github.com/bonjoski/coppermind/pkg/storage"
)

func appendSQLiteScopePredicate(query string, args []any, targetScope string, mode scope.Mode) (string, []any) {
	if targetScope == "" && mode != scope.ModeExact {
		return query, args
	}
	if mode == "" {
		mode = scope.ModeAncestors
	}
	if mode == scope.ModeAll {
		return query, args
	}
	switch mode {
	case scope.ModeExact:
		return query + " AND scope = ?", append(args, targetScope)
	case scope.ModeAncestors:
		anc := scope.Ancestors(targetScope)
		placeholders := strings.TrimRight(strings.Repeat("?,", len(anc)), ",")
		for _, a := range anc {
			args = append(args, a)
		}
		return query + " AND scope IN (" + placeholders + ")", args
	case scope.ModeSubtree:
		if targetScope == "" {
			return query, args
		}
		lo, hi := scope.SubtreeBounds(targetScope)
		return query + " AND (scope = ? OR (scope >= ? AND scope < ?))", append(args, targetScope, lo, hi)
	case scope.ModeLineage:
		if targetScope == "" {
			return query, args
		}
		anc := scope.Ancestors(targetScope)
		placeholders := strings.TrimRight(strings.Repeat("?,", len(anc)), ",")
		for _, a := range anc {
			args = append(args, a)
		}
		lo, hi := scope.SubtreeBounds(targetScope)
		return query + " AND (scope IN (" + placeholders + ") OR (scope >= ? AND scope < ?))", append(args, lo, hi)
	default:
		return query, args
	}
}

// Compile-time parity assertions ensuring SQLiteStore implements every capability interface.
var (
	_ storage.GraphStore       = (*SQLiteStore)(nil)
	_ storage.IndexedFileStore = (*SQLiteStore)(nil)
	_ storage.InboxStore       = (*SQLiteStore)(nil)
	_ storage.VectorAdminStore = (*SQLiteStore)(nil)
	_ storage.ExplorerStore    = (*SQLiteStore)(nil)
	_ storage.CartridgeStore   = (*SQLiteStore)(nil)
)

// ListTimeline returns chronological active/superseded non-derived memories ordered newest first.
func (s *SQLiteStore) ListTimeline(ctx context.Context, filter storage.TimelineFilter) ([]*brain.MemoryNode, error) {
	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	fetchLimit := limit
	if filter.Repo != "" {
		fetchLimit = limit * 4
		if fetchLimit > 800 {
			fetchLimit = 800
		}
	}

	query := `SELECT ` + sqliteMemoryColumns + `
	          FROM memory_nodes
	          WHERE derived = 0 AND (lifecycle_status IN ('ACTIVE', 'SUPERSEDED') OR lifecycle_status = '' OR lifecycle_status IS NULL)`
	var args []any
	if filter.Since != nil {
		query += " AND created_at >= ?"
		args = append(args, filter.Since.UnixNano())
	}
	query, args = appendSQLiteScopePredicate(query, args, filter.Scope, filter.ScopeMode)
	query += " ORDER BY created_at DESC LIMIT ?"
	args = append(args, fetchLimit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]*brain.MemoryNode, 0, limit)
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			continue
		}
		if filter.Repo != "" && (n.Metadata == nil || !strings.EqualFold(n.Metadata["git_repo"], filter.Repo)) {
			continue
		}
		out = append(out, n)
		if len(out) >= limit {
			break
		}
	}
	return out, rows.Err()
}

// ListProposals returns quarantined PROPOSED learnings awaiting human approval.
func (s *SQLiteStore) ListProposals(ctx context.Context, limit int) ([]*brain.MemoryNode, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+sqliteMemoryColumns+`
		FROM memory_nodes
		WHERE lifecycle_status = 'PROPOSED'
		ORDER BY created_at DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*brain.MemoryNode
	for rows.Next() {
		if n, err := scanNode(rows); err == nil {
			out = append(out, n)
		}
	}
	return out, rows.Err()
}

// GetLineage returns supersession ancestors and audit trail records for a memory node.
func (s *SQLiteStore) GetLineage(ctx context.Context, id string) ([]*brain.MemoryNode, []*storage.SupersessionAudit, error) {
	ancestors, err := s.GetAncestors(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	rawAudit, err := s.GetAuditTrail(ctx, id)
	if err != nil {
		return ancestors, nil, err
	}
	audit := make([]*storage.SupersessionAudit, 0, len(rawAudit))
	for _, r := range rawAudit {
		audit = append(audit, &storage.SupersessionAudit{
			ID:             r.ID,
			SupersedingID:  r.SupersedingID,
			SupersededID:   r.SupersededID,
			Rationale:      r.Rationale,
			AdvisoryRef:    r.AdvisoryRef,
			AuthorIdentity: r.AuthorIdentity,
			AuthorRole:     r.AuthorRole,
			CreatedAt:      r.CreatedAt,
		})
	}
	return ancestors, audit, nil
}

// ListScopes aggregates active non-derived memory and invariant counts per canonical scope.
func (s *SQLiteStore) ListScopes(ctx context.Context) ([]storage.ScopeSummary, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT scope,
		       COUNT(*) AS mem_count,
		       SUM(CASE WHEN authority_tier IN ('TIER_0_SOVEREIGN', 'TIER_1_ARCHITECTURE') THEN 1 ELSE 0 END) AS inv_count
		FROM memory_nodes
		WHERE derived = 0
		  AND (lifecycle_status = 'ACTIVE' OR lifecycle_status = '' OR lifecycle_status IS NULL)
		GROUP BY scope
		ORDER BY scope ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []storage.ScopeSummary
	for rows.Next() {
		var sc sql.NullString
		var memCnt, invCnt int
		if err := rows.Scan(&sc, &memCnt, &invCnt); err != nil {
			return nil, err
		}
		out = append(out, storage.ScopeSummary{
			Scope:          sc.String,
			Depth:          scope.Depth(sc.String),
			MemoryCount:    memCnt,
			InvariantCount: invCnt,
		})
	}
	return out, rows.Err()
}

// QueryActiveNodesForCartridge selects active, non-derived memory nodes matching cartridge export filters.
func (s *SQLiteStore) QueryActiveNodesForCartridge(ctx context.Context, filter storage.CartridgeFilter) ([]*brain.MemoryNode, error) {
	query := `SELECT ` + sqliteMemoryColumns + `
	          FROM memory_nodes
	          WHERE derived = 0 AND (lifecycle_status = 'ACTIVE' OR lifecycle_status = '' OR lifecycle_status IS NULL)`
	var args []any
	if filter.Category != "" {
		query += " AND category = ?"
		args = append(args, filter.Category)
	}
	if filter.Tier != "" {
		query += " AND authority_tier = ?"
		args = append(args, filter.Tier)
	}
	if filter.Since != nil {
		query += " AND created_at >= ?"
		args = append(args, filter.Since.UnixNano())
	}
	query, args = appendSQLiteScopePredicate(query, args, filter.Scope, filter.ScopeMode)
	query += " ORDER BY id ASC"

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*brain.MemoryNode
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		if filter.Repo != "" && (n.Metadata == nil || !strings.EqualFold(n.Metadata["git_repo"], filter.Repo)) {
			continue
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// ListExistingContentHashes returns the set of non-empty content_sha256 digests for cartridge deduplication.
func (s *SQLiteStore) ListExistingContentHashes(ctx context.Context) (map[string]bool, error) {
	hashes := make(map[string]bool)
	rows, err := s.db.QueryContext(ctx, `SELECT content_sha256 FROM memory_nodes WHERE content_sha256 != ''`)
	if err != nil {
		return hashes, err
	}
	defer rows.Close()
	for rows.Next() {
		var h string
		if rows.Scan(&h) == nil {
			hashes[h] = true
		}
	}
	return hashes, rows.Err()
}
