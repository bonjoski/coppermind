package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/embedding"
	"github.com/bonjoski/coppermind/pkg/graph"
	"github.com/bonjoski/coppermind/pkg/storage"
)

// Compile-time parity assertions ensuring PostgresStore implements every Profile A capability interface.
var (
	_ storage.GraphStore       = (*PostgresStore)(nil)
	_ storage.IndexedFileStore = (*PostgresStore)(nil)
	_ storage.InboxStore       = (*PostgresStore)(nil)
	_ storage.VectorAdminStore = (*PostgresStore)(nil)
	_ storage.ExplorerStore    = (*PostgresStore)(nil)
	_ storage.CartridgeStore   = (*PostgresStore)(nil)
)

// --- ACT-R Access Tracking ---

// IncrementAccessBatch updates access_count and last_accessed_at for trusted local workspace nodes.
func (s *PostgresStore) IncrementAccessBatch(ctx context.Context, ids []string, accessedAt time.Time) error {
	if len(ids) == 0 {
		return nil
	}
	if accessedAt.IsZero() {
		accessedAt = time.Now()
	}
	nowNano := accessedAt.UnixNano()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx, `UPDATE memory_nodes SET access_count = access_count + 1, last_accessed_at = $1 WHERE id = $2 AND provenance = 'TRUST_LOCAL_WORKSPACE'`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, id := range ids {
		if _, err := stmt.ExecContext(ctx, nowNano, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// --- GraphStore ---

// StoreEdges persists explicit knowledge graph edges in PostgreSQL.
func (s *PostgresStore) StoreEdges(ctx context.Context, edges []graph.Edge) error {
	if len(edges) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO memory_edges (id, source_id, target_id, target_entity, relation, weight, derived, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (id) DO NOTHING
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, e := range edges {
		if !graph.IsValidRelation(e.Relation) {
			return fmt.Errorf("invalid graph relation %q", e.Relation)
		}
		ts := e.CreatedAt
		if ts.IsZero() {
			ts = time.Now()
		}
		if _, err := stmt.ExecContext(ctx, e.ID, e.SourceID, e.TargetID, e.TargetEntity, string(e.Relation), e.Weight, e.Derived, ts.UnixNano()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// GetEdgesForNode returns all outbound and inbound edges connected to nodeID.
func (s *PostgresStore) GetEdgesForNode(ctx context.Context, nodeID string) ([]graph.Edge, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, source_id, target_id, target_entity, relation, weight, derived, created_at
		FROM memory_edges
		WHERE source_id = $1 OR target_id = $1
		ORDER BY weight DESC, created_at DESC
		LIMIT 100
	`, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []graph.Edge
	for rows.Next() {
		var e graph.Edge
		var rel string
		var createdNano int64
		if err := rows.Scan(&e.ID, &e.SourceID, &e.TargetID, &e.TargetEntity, &rel, &e.Weight, &e.Derived, &createdNano); err != nil {
			return nil, err
		}
		e.Relation = graph.RelationType(rel)
		e.CreatedAt = time.Unix(0, createdNano)
		out = append(out, e)
	}
	return out, rows.Err()
}

// GetNodesByEntity returns active memory nodes linked to a canonical graph entity.
func (s *PostgresStore) GetNodesByEntity(ctx context.Context, entity string, limit int) ([]*brain.MemoryNode, error) {
	if limit <= 0 || limit > graph.MaxExpandedNodes {
		limit = 20
	}
	cols := "m." + strings.ReplaceAll(postgresMemoryColumns, ", ", ", m.")
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT `+cols+`
		FROM memory_nodes m
		JOIN memory_edges e ON e.source_id = m.id
		WHERE e.target_entity = $1
		  AND (m.lifecycle_status = 'ACTIVE' OR m.lifecycle_status = '' OR m.lifecycle_status IS NULL)
		ORDER BY m.created_at DESC
		LIMIT $2
	`, entity, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	nowNano := time.Now().UnixNano()
	var out []*brain.MemoryNode
	for rows.Next() {
		n, err := scanPostgresNode(rows, nil)
		if err != nil {
			return nil, err
		}
		if n.ExpiresAt != nil && n.ExpiresAt.UnixNano() < nowNano {
			continue
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// ImpactForFile returns active invariants, decisions, observations, and chunks linked to relPath.
func (s *PostgresStore) ImpactForFile(ctx context.Context, relPath string, limit int) ([]*brain.MemoryNode, error) {
	ent := graph.NormalizeFileEntity(relPath)
	if ent == "" {
		return nil, fmt.Errorf("invalid relative file path %q", relPath)
	}
	return s.GetNodesByEntity(ctx, ent, limit)
}

func (s *PostgresStore) findPeerNodeIDsByEntity(ctx context.Context, entity string, limit int) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT source_id FROM memory_edges
		WHERE target_entity = $1
		LIMIT $2
	`, entity, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	return ids, rows.Err()
}

// ExpandGraphNeighbors performs bounded multi-hop BFS (<=2 hops, <=50 nodes) with monotonic untrusted taint isolation.
func (s *PostgresStore) ExpandGraphNeighbors(ctx context.Context, seedIDs []string, maxHops int, filter brain.MemoryFilter) ([]*brain.SearchResult, error) {
	if len(seedIDs) == 0 || maxHops <= 0 {
		return nil, nil
	}
	if maxHops > graph.MaxGraphHops {
		maxHops = graph.MaxGraphHops
	}

	visited := make(map[string]bool, len(seedIDs)+graph.MaxExpandedNodes)
	taintedPath := make(map[string]bool, len(seedIDs)+graph.MaxExpandedNodes)
	frontier := make([]string, 0, len(seedIDs))
	for _, sid := range seedIDs {
		if sid != "" && !visited[sid] {
			visited[sid] = true
			frontier = append(frontier, sid)
			if sNode, _ := s.GetByID(ctx, sid); sNode != nil && sNode.Provenance == brain.ProvenanceUntrustedWeb {
				taintedPath[sid] = true
			}
		}
	}

	linkReasons := make(map[string][]string)
	expandedIDs := make([]string, 0, graph.MaxExpandedNodes)

	for hop := 1; hop <= maxHops && len(frontier) > 0 && len(expandedIDs) < graph.MaxExpandedNodes; hop++ {
		nextFrontier := make([]string, 0, 16)
		for _, curID := range frontier {
			if len(expandedIDs) >= graph.MaxExpandedNodes {
				break
			}
			edges, err := s.GetEdgesForNode(ctx, curID)
			if err != nil {
				continue
			}
			curUntrusted := taintedPath[curID]
			if !curUntrusted {
				if curNode, _ := s.GetByID(ctx, curID); curNode != nil && curNode.Provenance == brain.ProvenanceUntrustedWeb {
					curUntrusted = true
					taintedPath[curID] = true
				}
			}

			for _, e := range edges {
				if len(expandedIDs) >= graph.MaxExpandedNodes {
					break
				}
				peerID := ""
				if e.SourceID == curID && e.TargetID != "" {
					peerID = e.TargetID
				} else if e.TargetID == curID && e.SourceID != "" {
					peerID = e.SourceID
				}
				if peerID != "" && !visited[peerID] {
					if curUntrusted {
						if pNode, _ := s.GetByID(ctx, peerID); pNode != nil && pNode.AuthorityTier == "TIER_0_SOVEREIGN" {
							continue
						}
						taintedPath[peerID] = true
					}
					visited[peerID] = true
					expandedIDs = append(expandedIDs, peerID)
					nextFrontier = append(nextFrontier, peerID)
					linkReasons[peerID] = append(linkReasons[peerID], fmt.Sprintf("%s:%s", e.Relation, curID))
				}

				if e.TargetEntity != "" && !strings.HasPrefix(e.TargetEntity, "repo:") {
					peers, err := s.findPeerNodeIDsByEntity(ctx, e.TargetEntity, 12)
					if err != nil {
						continue
					}
					for _, pid := range peers {
						if len(expandedIDs) >= graph.MaxExpandedNodes {
							break
						}
						if visited[pid] {
							continue
						}
						if curUntrusted {
							if pNode, _ := s.GetByID(ctx, pid); pNode != nil && pNode.AuthorityTier == "TIER_0_SOVEREIGN" {
								continue
							}
							taintedPath[pid] = true
						}
						visited[pid] = true
						expandedIDs = append(expandedIDs, pid)
						nextFrontier = append(nextFrontier, pid)
						linkReasons[pid] = append(linkReasons[pid], e.TargetEntity)
					}
				}
			}
		}
		frontier = nextFrontier
	}

	nowNano := time.Now().UnixNano()
	var results []*brain.SearchResult
	for _, id := range expandedIDs {
		node, err := s.GetByID(ctx, id)
		if err != nil || node == nil {
			continue
		}
		if !pgNodeMatchesFilter(node, filter, nowNano) {
			continue
		}
		if filter.Provenance == "" && node.Provenance == brain.ProvenanceUntrustedWeb {
			continue
		}
		results = append(results, &brain.SearchResult{
			Node:       node,
			Score:      0.55,
			GraphLinks: linkReasons[id],
		})
	}
	return results, nil
}

func pgNodeMatchesFilter(n *brain.MemoryNode, f brain.MemoryFilter, nowNano int64) bool {
	if n.ExpiresAt != nil && n.ExpiresAt.UnixNano() < nowNano {
		return false
	}
	if f.SessionID != "" && n.SessionID != f.SessionID {
		return false
	}
	if f.Category != "" && n.Category != f.Category {
		return false
	}
	if f.Provenance != "" && n.Provenance != f.Provenance {
		return false
	}
	if f.Derived != nil && n.Derived != *f.Derived {
		return false
	}
	if f.SourceLens != "" && n.SourceLens != f.SourceLens {
		return false
	}
	if f.AuthorityTier != "" && !strings.EqualFold(n.AuthorityTier, f.AuthorityTier) {
		return false
	}
	if !f.IncludeSuperseded {
		if f.LifecycleStatus != "" && !strings.EqualFold(n.LifecycleStatus, f.LifecycleStatus) {
			return false
		}
		if f.LifecycleStatus == "" && n.LifecycleStatus != "" && !strings.EqualFold(n.LifecycleStatus, "ACTIVE") {
			return false
		}
	}
	if f.CreatedAfter != nil && n.CreatedAt.UnixNano() < f.CreatedAfter.UnixNano() {
		return false
	}
	if f.CreatedBefore != nil && n.CreatedAt.UnixNano() > f.CreatedBefore.UnixNano() {
		return false
	}
	if f.GitRepo != "" && (n.Metadata == nil || n.Metadata["git_repo"] != f.GitRepo) {
		return false
	}
	if f.GitBranch != "" && (n.Metadata == nil || n.Metadata["git_branch"] != f.GitBranch) {
		return false
	}
	return true
}

// GetGraphSubgraph returns bounded nodes and edges for local Brain Explorer visualization.
func (s *PostgresStore) GetGraphSubgraph(ctx context.Context, centerID string, maxNodes int, maxEdges int) ([]*brain.MemoryNode, []graph.Edge, error) {
	if maxNodes <= 0 || maxNodes > 100 {
		maxNodes = 100
	}
	if maxEdges <= 0 || maxEdges > 250 {
		maxEdges = 250
	}

	var nodes []*brain.MemoryNode
	nodeSet := make(map[string]bool)
	if centerID != "" {
		if c, err := s.GetByID(ctx, centerID); err == nil && c != nil {
			nodes = append(nodes, c)
			nodeSet[c.ID] = true
		}
		neighbors, _ := s.ExpandGraphNeighbors(ctx, []string{centerID}, 2, brain.MemoryFilter{Limit: maxNodes - 1})
		for _, n := range neighbors {
			if len(nodes) >= maxNodes {
				break
			}
			if n.Node != nil && !nodeSet[n.Node.ID] {
				nodes = append(nodes, n.Node)
				nodeSet[n.Node.ID] = true
			}
		}
	} else {
		rows, err := s.db.QueryContext(ctx, `
			SELECT `+postgresMemoryColumns+`
			FROM memory_nodes
			WHERE lifecycle_status = 'ACTIVE' OR lifecycle_status = '' OR lifecycle_status IS NULL
			ORDER BY created_at DESC
			LIMIT $1
		`, maxNodes)
		if err != nil {
			return nil, nil, err
		}
		for rows.Next() {
			if n, err := scanPostgresNode(rows, nil); err == nil && n != nil {
				nodes = append(nodes, n)
				nodeSet[n.ID] = true
			}
		}
		rows.Close()
	}

	var edges []graph.Edge
	edgeSeen := make(map[string]bool)
	for _, n := range nodes {
		if len(edges) >= maxEdges {
			break
		}
		nEdges, err := s.GetEdgesForNode(ctx, n.ID)
		if err != nil {
			continue
		}
		for _, e := range nEdges {
			if len(edges) >= maxEdges {
				break
			}
			if !edgeSeen[e.ID] {
				edgeSeen[e.ID] = true
				edges = append(edges, e)
			}
		}
	}
	return nodes, edges, nil
}

// --- IndexedFileStore ---

// ListIndexedFiles loads the hash-incremental manifest for repoRoot from PostgreSQL.
func (s *PostgresStore) ListIndexedFiles(ctx context.Context, repoRoot string) (map[string]storage.IndexedFileRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT repo_root, rel_path, content_sha256, chunk_ids_json, indexed_at
		FROM indexed_files
		WHERE repo_root = $1
	`, repoRoot)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[string]storage.IndexedFileRecord)
	for rows.Next() {
		var rec storage.IndexedFileRecord
		var idsJSON []byte
		var indexedNano int64
		if err := rows.Scan(&rec.RepoRoot, &rec.RelPath, &rec.ContentSHA256, &idsJSON, &indexedNano); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(idsJSON, &rec.ChunkIDs)
		rec.IndexedAt = time.Unix(0, indexedNano)
		out[rec.RelPath] = rec
	}
	return out, rows.Err()
}

// UpsertIndexedFile records or updates a file's SHA-256 and active chunk IDs.
func (s *PostgresStore) UpsertIndexedFile(ctx context.Context, rec storage.IndexedFileRecord) error {
	if rec.IndexedAt.IsZero() {
		rec.IndexedAt = time.Now()
	}
	idsBytes, _ := json.Marshal(rec.ChunkIDs)
	if rec.ChunkIDs == nil {
		idsBytes = []byte("[]")
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO indexed_files (repo_root, rel_path, content_sha256, chunk_ids_json, indexed_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (repo_root, rel_path) DO UPDATE SET
			content_sha256 = EXCLUDED.content_sha256,
			chunk_ids_json = EXCLUDED.chunk_ids_json,
			indexed_at = EXCLUDED.indexed_at
	`, rec.RepoRoot, rec.RelPath, rec.ContentSHA256, idsBytes, rec.IndexedAt.UnixNano())
	return err
}

// DeleteIndexedChunks atomically deletes stale chunks and their incident edges.
func (s *PostgresStore) DeleteIndexedChunks(ctx context.Context, chunkIDs []string) error {
	if len(chunkIDs) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, id := range chunkIDs {
		_, _ = tx.ExecContext(ctx, "DELETE FROM memory_edges WHERE source_id = $1 OR target_id = $1", id)
		if _, err := tx.ExecContext(ctx, "DELETE FROM memory_nodes WHERE id = $1", id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// PruneIndexedFile atomically deletes a removed file's chunks and manifest entry.
func (s *PostgresStore) PruneIndexedFile(ctx context.Context, repoRoot, relPath string, chunkIDs []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, id := range chunkIDs {
		_, _ = tx.ExecContext(ctx, "DELETE FROM memory_edges WHERE source_id = $1 OR target_id = $1", id)
		_, _ = tx.ExecContext(ctx, "DELETE FROM memory_nodes WHERE id = $1", id)
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM indexed_files WHERE repo_root = $1 AND rel_path = $2", repoRoot, relPath); err != nil {
		return err
	}
	return tx.Commit()
}

// --- InboxStore ---

// EnqueuePendingTicket inserts a deduplicated pending lens ticket into PostgreSQL.
func (s *PostgresStore) EnqueuePendingTicket(ctx context.Context, ticket storage.PendingLensTicket) error {
	if strings.TrimSpace(ticket.LensName) == "" || strings.TrimSpace(ticket.MemoryID) == "" {
		return fmt.Errorf("lens_name and memory_id are required")
	}
	if ticket.ID == "" {
		sum := sha256.Sum256([]byte(ticket.LensName + ":" + ticket.MemoryID))
		ticket.ID = "tkt_" + hex.EncodeToString(sum[:8])
	}
	if ticket.Status == "" {
		ticket.Status = "pending"
	}
	if ticket.CreatedAt.IsZero() {
		ticket.CreatedAt = time.Now()
	}
	sinksJSON, _ := json.Marshal(ticket.MatchedSinks)
	if ticket.MatchedSinks == nil {
		sinksJSON = []byte("[]")
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO pending_lens_tickets (
			id, lens_name, commit_sha, memory_id, repo_name, branch_name, summary, matched_sinks_json, status, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT DO NOTHING
	`, ticket.ID, ticket.LensName, ticket.CommitSHA, ticket.MemoryID, ticket.RepoName, ticket.BranchName,
		ticket.Summary, sinksJSON, ticket.Status, ticket.CreatedAt.UnixNano())
	return err
}

// ListPendingTickets returns inbox tickets filtered by optional lensName and status.
func (s *PostgresStore) ListPendingTickets(ctx context.Context, lensName, status string, limit int) ([]storage.PendingLensTicket, error) {
	if limit <= 0 || limit > 100 {
		limit = 25
	}
	query := `SELECT id, lens_name, commit_sha, memory_id, repo_name, branch_name, summary, matched_sinks_json, status, created_at, resolved_at FROM pending_lens_tickets WHERE 1=1`
	var args []any
	idx := 1
	if lensName != "" && lensName != "all" {
		query += fmt.Sprintf(" AND lens_name = $%d", idx)
		args = append(args, lensName)
		idx++
	}
	if status != "" {
		query += fmt.Sprintf(" AND status = $%d", idx)
		args = append(args, status)
		idx++
	}
	query += fmt.Sprintf(" ORDER BY created_at ASC LIMIT $%d", idx)
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []storage.PendingLensTicket
	for rows.Next() {
		var t storage.PendingLensTicket
		var sinksJSON []byte
		var createdNano int64
		var resolvedNano sql.NullInt64
		if err := rows.Scan(&t.ID, &t.LensName, &t.CommitSHA, &t.MemoryID, &t.RepoName, &t.BranchName, &t.Summary, &sinksJSON, &t.Status, &createdNano, &resolvedNano); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(sinksJSON, &t.MatchedSinks)
		t.CreatedAt = time.Unix(0, createdNano)
		if resolvedNano.Valid {
			rt := time.Unix(0, resolvedNano.Int64)
			t.ResolvedAt = &rt
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// PeekOldestPendingTicket returns the oldest pending ticket for lensName (or any lens if empty).
func (s *PostgresStore) PeekOldestPendingTicket(ctx context.Context, lensName string) (*storage.PendingLensTicket, error) {
	tickets, err := s.ListPendingTickets(ctx, lensName, "pending", 1)
	if err != nil || len(tickets) == 0 {
		return nil, err
	}
	return &tickets[0], nil
}

// ResolvePendingTicket marks a pending ticket completed or dismissed.
func (s *PostgresStore) ResolvePendingTicket(ctx context.Context, id, newStatus string) error {
	if newStatus != "completed" && newStatus != "dismissed" {
		return fmt.Errorf("invalid ticket status %q (must be completed or dismissed)", newStatus)
	}
	_, err := s.db.ExecContext(ctx, `UPDATE pending_lens_tickets SET status = $1, resolved_at = $2 WHERE id = $3`, newStatus, time.Now().UnixNano(), id)
	return err
}

// ResolvePendingTicketsByMemory marks pending tickets matching (lensName, memoryID) completed.
func (s *PostgresStore) ResolvePendingTicketsByMemory(ctx context.Context, lensName, memoryID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE pending_lens_tickets SET status = 'completed', resolved_at = $1 WHERE lens_name = $2 AND memory_id = $3 AND status = 'pending'`,
		time.Now().UnixNano(), lensName, memoryID)
	return err
}

// --- VectorAdminStore ---

// GetVectorCoverage reports active memory counts broken down by embedding_model.
func (s *PostgresStore) GetVectorCoverage(ctx context.Context, activeModel string) (*storage.VectorCoverage, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT COALESCE(embedding_model, ''), COUNT(*) FROM memory_nodes GROUP BY embedding_model`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cov := &storage.VectorCoverage{ByModel: make(map[string]int)}
	for rows.Next() {
		var model string
		var cnt int
		if err := rows.Scan(&model, &cnt); err != nil {
			return nil, err
		}
		if model == "" {
			model = "local-hash-128"
		}
		cov.ByModel[model] += cnt
		cov.TotalNodes += cnt
		if model == activeModel {
			cov.MatchingNodes += cnt
		}
	}
	return cov, rows.Err()
}

// ReindexVectors upgrades pgvector column dimensionality if needed and re-embeds mismatched nodes in micro-batches.
func (s *PostgresStore) ReindexVectors(ctx context.Context, emb brain.Embedder, modelName string, batchSize int, dryRun bool) (*storage.ReindexStats, error) {
	start := time.Now()
	if emb == nil {
		return nil, fmt.Errorf("embedder is required")
	}
	if modelName == "" {
		modelName = embedding.ModelNameFor(emb)
	}
	if batchSize <= 0 {
		batchSize = 128
	}
	dim := emb.Dimension()

	rows, err := s.db.QueryContext(ctx, `SELECT id, content, COALESCE(embedding_model, ''), COALESCE(embedding_dim, 0) FROM memory_nodes`)
	if err != nil {
		return nil, err
	}
	type candidate struct {
		id      string
		content string
	}
	var toUpdate []candidate
	stats := &storage.ReindexStats{ModelName: modelName, Dimension: dim}
	for rows.Next() {
		var id, content, curModel string
		var curDim int
		if err := rows.Scan(&id, &content, &curModel, &curDim); err != nil {
			rows.Close()
			return nil, err
		}
		stats.TotalNodes++
		if curModel == modelName && curDim == dim {
			stats.Skipped++
			continue
		}
		toUpdate = append(toUpdate, candidate{id: id, content: content})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if dryRun || len(toUpdate) == 0 {
		stats.Reindexed = len(toUpdate)
		stats.Duration = time.Since(start)
		return stats, nil
	}

	// Safely migrate pgvector column dimension if existing table was created with a different dimension (e.g. 128 -> 256)
	var colType string
	_ = s.db.QueryRowContext(ctx, `
		SELECT format_type(a.atttypid, a.atttypmod)
		FROM pg_attribute a
		JOIN pg_class c ON a.attrelid = c.oid
		WHERE c.relname = 'memory_nodes' AND a.attname = 'vector_data' AND a.attnum > 0
	`).Scan(&colType)
	wantType := fmt.Sprintf("vector(%d)", dim)
	if colType != "" && colType != wantType {
		// Force full re-embed of all nodes when resizing the pgvector column
		if _, err := s.db.ExecContext(ctx, fmt.Sprintf(`ALTER TABLE memory_nodes ALTER COLUMN vector_data TYPE vector(%d) USING NULL`, dim)); err != nil {
			return nil, fmt.Errorf("failed resizing pgvector column from %s to %s: %w", colType, wantType, err)
		}
		s.dimension = dim
		// Reload all nodes since vector_data was cleared during dimension change
		allRows, qErr := s.db.QueryContext(ctx, `SELECT id, content FROM memory_nodes`)
		if qErr != nil {
			return nil, qErr
		}
		toUpdate = toUpdate[:0]
		for allRows.Next() {
			var c candidate
			if allRows.Scan(&c.id, &c.content) == nil {
				toUpdate = append(toUpdate, c)
			}
		}
		allRows.Close()
		stats.Skipped = 0
	}

	for i := 0; i < len(toUpdate); i += batchSize {
		end := i + batchSize
		if end > len(toUpdate) {
			end = len(toUpdate)
		}
		batch := toUpdate[i:end]
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return stats, err
		}
		stmt, err := tx.PrepareContext(ctx, `UPDATE memory_nodes SET vector_data = $1, embedding_model = $2, embedding_dim = $3, updated_at = $4 WHERE id = $5`)
		if err != nil {
			_ = tx.Rollback()
			return stats, err
		}
		nowNano := time.Now().UnixNano()
		for _, c := range batch {
			vec, eErr := emb.Embed(ctx, c.content)
			if eErr != nil {
				stmt.Close()
				_ = tx.Rollback()
				return stats, eErr
			}
			if _, err := stmt.ExecContext(ctx, FormatVector(vec), modelName, dim, nowNano, c.id); err != nil {
				stmt.Close()
				_ = tx.Rollback()
				return stats, err
			}
			stats.Reindexed++
		}
		stmt.Close()
		if err := tx.Commit(); err != nil {
			return stats, err
		}
	}

	stats.Duration = time.Since(start)
	return stats, nil
}

// --- ExplorerStore ---

// ListTimeline returns chronological active/superseded non-derived memories ordered newest first.
func (s *PostgresStore) ListTimeline(ctx context.Context, filter storage.TimelineFilter) ([]*brain.MemoryNode, error) {
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
	query := `SELECT ` + postgresMemoryColumns + `
	          FROM memory_nodes
	          WHERE derived = FALSE AND (lifecycle_status IN ('ACTIVE', 'SUPERSEDED') OR lifecycle_status = '' OR lifecycle_status IS NULL)`
	var args []any
	idx := 1
	if filter.Since != nil {
		query += fmt.Sprintf(" AND created_at >= $%d", idx)
		args = append(args, filter.Since.UnixNano())
		idx++
	}
	query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d", idx)
	args = append(args, fetchLimit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]*brain.MemoryNode, 0, limit)
	for rows.Next() {
		n, err := scanPostgresNode(rows, nil)
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
func (s *PostgresStore) ListProposals(ctx context.Context, limit int) ([]*brain.MemoryNode, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+postgresMemoryColumns+`
		FROM memory_nodes
		WHERE lifecycle_status = 'PROPOSED'
		ORDER BY created_at DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*brain.MemoryNode
	for rows.Next() {
		if n, err := scanPostgresNode(rows, nil); err == nil {
			out = append(out, n)
		}
	}
	return out, rows.Err()
}

// GetLineage traverses supersession ancestors and returns audit records for id.
func (s *PostgresStore) GetLineage(ctx context.Context, id string) ([]*brain.MemoryNode, []*storage.SupersessionAudit, error) {
	var ancestors []*brain.MemoryNode
	visited := make(map[string]struct{})
	curID := id
	for curID != "" {
		if _, seen := visited[curID]; seen {
			break
		}
		visited[curID] = struct{}{}
		node, err := s.GetByID(ctx, curID)
		if err != nil {
			if err == sql.ErrNoRows {
				break
			}
			return nil, nil, err
		}
		ancestors = append(ancestors, node)
		curID = node.SupersedesID
	}
	rawAudit, err := s.GetSupersessionHistory(ctx, id)
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

// --- CartridgeStore ---

// QueryActiveNodesForCartridge selects active, non-derived nodes matching cartridge export filters.
func (s *PostgresStore) QueryActiveNodesForCartridge(ctx context.Context, repo, category, tier string, since *time.Time) ([]*brain.MemoryNode, error) {
	query := `SELECT ` + postgresMemoryColumns + `
	          FROM memory_nodes
	          WHERE derived = FALSE AND (lifecycle_status = 'ACTIVE' OR lifecycle_status = '' OR lifecycle_status IS NULL)`
	var args []any
	idx := 1
	if category != "" {
		query += fmt.Sprintf(" AND category = $%d", idx)
		args = append(args, category)
		idx++
	}
	if tier != "" {
		query += fmt.Sprintf(" AND authority_tier = $%d", idx)
		args = append(args, tier)
		idx++
	}
	if since != nil {
		query += fmt.Sprintf(" AND created_at >= $%d", idx)
		args = append(args, since.UnixNano())
		idx++
	}
	query += " ORDER BY id ASC"

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*brain.MemoryNode
	for rows.Next() {
		n, err := scanPostgresNode(rows, nil)
		if err != nil {
			return nil, err
		}
		if repo != "" && (n.Metadata == nil || !strings.EqualFold(n.Metadata["git_repo"], repo)) {
			continue
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// ListExistingContentHashes returns the set of non-empty content_sha256 digests for cartridge deduplication.
func (s *PostgresStore) ListExistingContentHashes(ctx context.Context) (map[string]bool, error) {
	hashes := make(map[string]bool)
	rows, err := s.db.QueryContext(ctx, `SELECT content_sha256 FROM memory_nodes WHERE content_sha256 IS NOT NULL AND content_sha256 != ''`)
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
