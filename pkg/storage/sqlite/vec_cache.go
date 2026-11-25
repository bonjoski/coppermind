package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/embedding"
	"github.com/bonjoski/coppermind/pkg/storage"
)

// VectorSlabEntry holds a lightweight immutable in-memory projection of a memory node
// for lock-free sub-2ms cosine scanning without per-query SQLite BLOB deserialization.
type VectorSlabEntry struct {
	ID              string
	SessionID       string
	Category        string
	Provenance      brain.ProvenanceTier
	AuthorityTier   string
	LifecycleStatus string
	SourceLens      string
	Severity        string
	Status          string
	Derived         bool
	GitRepo         string
	GitBranch       string
	ParentIDs       []string
	CreatedAtNano   int64
	ExpiresAtNano   int64 // 0 means no expiration
	EmbeddingModel  string
	EmbeddingDim    int
	Vector          []float32
}

type vectorSnapshot struct {
	entries []VectorSlabEntry
	byID    map[string]int
}

// vectorCache provides lock-free reads via atomic.Pointer copy-on-write snapshots.
type vectorCache struct {
	snap atomic.Pointer[vectorSnapshot]
	mu   sync.Mutex // serializes snapshot rebuild/updates only; readers never lock
}

func newVectorCache() *vectorCache {
	return &vectorCache{}
}

func (c *vectorCache) get() *vectorSnapshot {
	return c.snap.Load()
}

func (c *vectorCache) invalidate() {
	c.mu.Lock()
	c.snap.Store(nil)
	c.mu.Unlock()
}

func (c *vectorCache) set(entries []VectorSlabEntry) {
	byID := make(map[string]int, len(entries))
	for i, e := range entries {
		byID[e.ID] = i
	}
	c.snap.Store(&vectorSnapshot{
		entries: entries,
		byID:    byID,
	})
}

func (c *vectorCache) upsert(node *brain.MemoryNode) {
	if node == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	cur := c.snap.Load()
	if cur == nil {
		return // lazy load will pick up DB state
	}
	entry := nodeToSlabEntry(node)
	nextEntries := make([]VectorSlabEntry, len(cur.entries), len(cur.entries)+1)
	copy(nextEntries, cur.entries)
	if idx, ok := cur.byID[node.ID]; ok {
		nextEntries[idx] = entry
	} else {
		nextEntries = append(nextEntries, entry)
	}
	c.set(nextEntries)
}

func (c *vectorCache) delete(id string) {
	if id == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	cur := c.snap.Load()
	if cur == nil {
		return
	}
	idx, ok := cur.byID[id]
	if !ok {
		return
	}
	nextEntries := make([]VectorSlabEntry, 0, len(cur.entries)-1)
	nextEntries = append(nextEntries, cur.entries[:idx]...)
	nextEntries = append(nextEntries, cur.entries[idx+1:]...)
	c.set(nextEntries)
}

func nodeToSlabEntry(node *brain.MemoryNode) VectorSlabEntry {
	var exp int64
	if node.ExpiresAt != nil {
		exp = node.ExpiresAt.UnixNano()
	}
	var gitRepo, gitBranch string
	if node.Metadata != nil {
		gitRepo = node.Metadata["git_repo"]
		gitBranch = node.Metadata["git_branch"]
	}
	dim := node.EmbeddingDim
	if dim == 0 {
		dim = len(node.Vector)
	}
	vecCopy := make([]float32, len(node.Vector))
	copy(vecCopy, node.Vector)
	parentsCopy := make([]string, len(node.ParentIDs))
	copy(parentsCopy, node.ParentIDs)

	return VectorSlabEntry{
		ID:              node.ID,
		SessionID:       node.SessionID,
		Category:        node.Category,
		Provenance:      node.Provenance,
		AuthorityTier:   node.AuthorityTier,
		LifecycleStatus: node.LifecycleStatus,
		SourceLens:      node.SourceLens,
		Severity:        node.Severity,
		Status:          node.Status,
		Derived:         node.Derived,
		GitRepo:         gitRepo,
		GitBranch:       gitBranch,
		ParentIDs:       parentsCopy,
		CreatedAtNano:   node.CreatedAt.UnixNano(),
		ExpiresAtNano:   exp,
		EmbeddingModel:  node.EmbeddingModel,
		EmbeddingDim:    dim,
		Vector:          vecCopy,
	}
}

func (s *SQLiteStore) loadVectorSnapshot(ctx context.Context) (*vectorSnapshot, error) {
	if snap := s.vecCache.get(); snap != nil {
		return snap, nil
	}
	s.vecCache.mu.Lock()
	defer s.vecCache.mu.Unlock()
	if snap := s.vecCache.get(); snap != nil {
		return snap, nil
	}

	rows, err := s.db.QueryContext(ctx, "SELECT "+sqliteMemoryColumns+" FROM memory_nodes")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []VectorSlabEntry
	for rows.Next() {
		node, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		entries = append(entries, nodeToSlabEntry(node))
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	s.vecCache.set(entries)
	return s.vecCache.get(), nil
}

func entryMatchesFilter(e VectorSlabEntry, filter brain.MemoryFilter, nowNano int64) bool {
	if e.ExpiresAtNano > 0 && e.ExpiresAtNano < nowNano {
		return false
	}
	if filter.SessionID != "" && e.SessionID != filter.SessionID {
		return false
	}
	if filter.Category != "" && e.Category != filter.Category {
		return false
	}
	if filter.Provenance != "" && e.Provenance != filter.Provenance {
		return false
	}
	if filter.Derived != nil && e.Derived != *filter.Derived {
		return false
	}
	if filter.SourceLens != "" && e.SourceLens != filter.SourceLens {
		return false
	}
	if filter.Severity != "" && !strings.EqualFold(e.Severity, filter.Severity) {
		return false
	}
	if filter.Status != "" && !strings.EqualFold(e.Status, filter.Status) {
		return false
	}
	if filter.GitRepo != "" && e.GitRepo != filter.GitRepo {
		return false
	}
	if filter.GitBranch != "" && e.GitBranch != filter.GitBranch {
		return false
	}
	if !filter.IncludeSuperseded {
		if filter.LifecycleStatus != "" {
			if e.LifecycleStatus != filter.LifecycleStatus {
				return false
			}
		} else if e.LifecycleStatus != "ACTIVE" && e.LifecycleStatus != "" {
			return false
		}
	} else if filter.LifecycleStatus != "" && e.LifecycleStatus != filter.LifecycleStatus {
		return false
	}
	if filter.AuthorityTier != "" && e.AuthorityTier != filter.AuthorityTier {
		return false
	}
	if filter.CreatedAfter != nil && e.CreatedAtNano < filter.CreatedAfter.UnixNano() {
		return false
	}
	if filter.CreatedBefore != nil && e.CreatedAtNano > filter.CreatedBefore.UnixNano() {
		return false
	}
	if filter.ParentID != "" {
		matched := false
		for _, pid := range e.ParentIDs {
			if pid == filter.ParentID {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// IncrementAccessBatch updates access_count and last_accessed_at in a single serialized write tx.
func (s *SQLiteStore) IncrementAccessBatch(ctx context.Context, ids []string, accessedAt time.Time) error {
	if len(ids) == 0 {
		return nil
	}
	if accessedAt.IsZero() {
		accessedAt = time.Now()
	}
	nowNano := accessedAt.UnixNano()
	return s.RunWriteTx(ctx, func(tx *sql.Tx) error {
		stmt, err := tx.Prepare(`UPDATE memory_nodes SET access_count = access_count + 1, last_accessed_at = ? WHERE id = ? AND provenance = 'TRUST_LOCAL_WORKSPACE'`)
		if err != nil {
			return err
		}
		defer stmt.Close()
		for _, id := range ids {
			if _, err := stmt.Exec(nowNano, id); err != nil {
				return err
			}
		}
		return nil
	})
}

// ReindexStats aliases the backend-agnostic vector reindex statistics.
type ReindexStats = storage.ReindexStats

// VectorCoverage aliases the backend-agnostic vector model coverage summary.
type VectorCoverage = storage.VectorCoverage

// GetVectorCoverage reports active memory counts broken down by embedding_model.
func (s *SQLiteStore) GetVectorCoverage(ctx context.Context, activeModel string) (*VectorCoverage, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT embedding_model, COUNT(*) FROM memory_nodes GROUP BY embedding_model`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cov := &VectorCoverage{ByModel: make(map[string]int)}
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

// ReindexVectors re-embeds all memory nodes whose embedding_model or embedding_dim does not match
// the supplied embedder, committing in bounded micro-batches through the single-writer ring.
func (s *SQLiteStore) ReindexVectors(ctx context.Context, emb brain.Embedder, modelName string, batchSize int, dryRun bool) (*ReindexStats, error) {
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

	rows, err := s.db.QueryContext(ctx, `SELECT id, content, embedding_model, embedding_dim FROM memory_nodes`)
	if err != nil {
		return nil, err
	}
	type candidate struct {
		id      string
		content string
	}
	var toUpdate []candidate
	stats := &ReindexStats{ModelName: modelName, Dimension: dim}

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

	type encodedRow struct {
		id   string
		blob []byte
	}
	for i := 0; i < len(toUpdate); i += batchSize {
		if ctx.Err() != nil {
			return stats, ctx.Err()
		}
		end := i + batchSize
		if end > len(toUpdate) {
			end = len(toUpdate)
		}
		batch := make([]encodedRow, 0, end-i)
		for _, cand := range toUpdate[i:end] {
			vec, err := emb.Embed(ctx, cand.content)
			if err != nil {
				return stats, fmt.Errorf("failed embedding node %s: %w", cand.id, err)
			}
			batch = append(batch, encodedRow{id: cand.id, blob: encodeVector(vec)})
		}
		if err := s.RunWriteTx(ctx, func(tx *sql.Tx) error {
			stmt, err := tx.Prepare(`UPDATE memory_nodes SET vector_blob = ?, embedding_model = ?, embedding_dim = ? WHERE id = ?`)
			if err != nil {
				return err
			}
			defer stmt.Close()
			for _, item := range batch {
				if _, err := stmt.Exec(item.blob, modelName, dim, item.id); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return stats, err
		}
		stats.Reindexed += len(batch)
	}

	s.vecCache.invalidate()
	stats.Duration = time.Since(start)
	return stats, nil
}

// scoredEntry pairs a slab index with a cosine score for fast top-K extraction.
type scoredEntry struct {
	id    string
	score float32
}

func topKScored(scored []scoredEntry, limit int) []scoredEntry {
	sort.Slice(scored, func(i, j int) bool {
		return scored[i].score > scored[j].score
	})
	if limit > 0 && len(scored) > limit {
		return scored[:limit]
	}
	return scored
}
