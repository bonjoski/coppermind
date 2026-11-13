package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bonjoski/coppermind/pkg/brain"
	_ "github.com/lib/pq"
)

// PostgresStore implements brain.MemoryStore backed by PostgreSQL 17 + pgvector.
type PostgresStore struct {
	db        *sql.DB
	dimension int
}

// Config provides connection settings for PostgreSQL.
type Config struct {
	URL       string
	Dimension int
}

// NewPostgresStore creates and initializes a PostgreSQL memory store.
func NewPostgresStore(ctx context.Context, cfg Config) (*PostgresStore, error) {
	if cfg.Dimension <= 0 {
		cfg.Dimension = 128
	}

	db, err := sql.Open("postgres", cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to open postgres connection: %w", err)
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to connect to postgres: %w", err)
	}

	store := &PostgresStore{
		db:        db,
		dimension: cfg.Dimension,
	}

	if err := store.migrate(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to run postgres migrations: %w", err)
	}

	return store, nil
}

func (s *PostgresStore) migrate(ctx context.Context) error {
	schema := fmt.Sprintf(`
	CREATE EXTENSION IF NOT EXISTS vector;

	CREATE TABLE IF NOT EXISTS memory_nodes (
		id VARCHAR(64) PRIMARY KEY,
		session_id VARCHAR(128) NOT NULL,
		category VARCHAR(64) NOT NULL,
		content TEXT NOT NULL,
		vector_data vector(%d),
		provenance VARCHAR(64) NOT NULL,
		taint_score DOUBLE PRECISION NOT NULL DEFAULT 0.0,
		metadata_json JSONB,
		created_at BIGINT NOT NULL,
		updated_at BIGINT NOT NULL,
		prev_hash VARCHAR(64) NOT NULL,
		hash VARCHAR(64) NOT NULL,
		expires_at BIGINT
	);

	CREATE INDEX IF NOT EXISTS idx_pg_session_id ON memory_nodes(session_id);
	CREATE INDEX IF NOT EXISTS idx_pg_category ON memory_nodes(category);
	CREATE INDEX IF NOT EXISTS idx_pg_created_at ON memory_nodes(created_at);
	CREATE INDEX IF NOT EXISTS idx_pg_expires_at ON memory_nodes(expires_at);
	CREATE INDEX IF NOT EXISTS idx_pg_content_fts ON memory_nodes USING gin(to_tsvector('english', content));
	`, s.dimension)

	_, err := s.db.ExecContext(ctx, schema)
	return err
}

// FormatVector converts a float32 slice into pgvector text representation: "[0.1,0.2,...]"
func FormatVector(vec []float32) string {
	if len(vec) == 0 {
		return "[]"
	}
	var sb strings.Builder
	sb.WriteByte('[')
	for i, v := range vec {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(strconv.FormatFloat(float64(v), 'f', 6, 32))
	}
	sb.WriteByte(']')
	return sb.String()
}

// ParseVector parses a pgvector string "[0.1,0.2,...]" back into []float32.
func ParseVector(str string) ([]float32, error) {
	str = strings.Trim(strings.TrimSpace(str), "[]")
	if str == "" {
		return nil, nil
	}
	parts := strings.Split(str, ",")
	vec := make([]float32, len(parts))
	for i, p := range parts {
		val, err := strconv.ParseFloat(strings.TrimSpace(p), 32)
		if err != nil {
			return nil, err
		}
		vec[i] = float32(val)
	}
	return vec, nil
}

// ComputeNodeHash computes the SHA-256 Merkle chain hash.
func ComputeNodeHash(prevHash, id, sessionID, category, content string, createdAtNano int64) string {
	h := sha256.New()
	h.Write([]byte(prevHash))
	h.Write([]byte(id))
	h.Write([]byte(sessionID))
	h.Write([]byte(category))
	h.Write([]byte(content))
	h.Write([]byte(strconv.FormatInt(createdAtNano, 10)))
	return hex.EncodeToString(h.Sum(nil))
}

// Store persists a memory node into PostgreSQL.
func (s *PostgresStore) Store(ctx context.Context, node *brain.MemoryNode) error {
	if node.ID == "" {
		return fmt.Errorf("node ID cannot be empty")
	}
	if node.CreatedAt.IsZero() {
		node.CreatedAt = time.Now()
	}
	if node.UpdatedAt.IsZero() {
		node.UpdatedAt = time.Now()
	}

	// Compute Merkle prev_hash if not populated
	if node.Hash == "" {
		var prevHash string
		err := s.db.QueryRowContext(ctx, "SELECT hash FROM memory_nodes WHERE session_id = $1 ORDER BY created_at DESC LIMIT 1", node.SessionID).Scan(&prevHash)
		if err != nil && err != sql.ErrNoRows {
			return fmt.Errorf("failed to fetch prev_hash: %w", err)
		}
		node.PrevHash = prevHash
		node.Hash = ComputeNodeHash(prevHash, node.ID, node.SessionID, node.Category, node.Content, node.CreatedAt.UnixNano())
	}

	var metaJSON []byte
	if len(node.Metadata) > 0 {
		metaJSON, _ = json.Marshal(node.Metadata)
	}

	var expiresAtNano *int64
	if node.ExpiresAt != nil {
		exp := node.ExpiresAt.UnixNano()
		expiresAtNano = &exp
	}

	vecStr := FormatVector(node.Vector)

	query := `
	INSERT INTO memory_nodes (
		id, session_id, category, content, vector_data, provenance, taint_score, metadata_json, created_at, updated_at, prev_hash, hash, expires_at
	) VALUES (
		$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
	)
	ON CONFLICT (id) DO UPDATE SET
		category = EXCLUDED.category,
		content = EXCLUDED.content,
		vector_data = EXCLUDED.vector_data,
		provenance = EXCLUDED.provenance,
		taint_score = EXCLUDED.taint_score,
		metadata_json = EXCLUDED.metadata_json,
		updated_at = EXCLUDED.updated_at,
		expires_at = EXCLUDED.expires_at;
	`

	_, err := s.db.ExecContext(ctx, query,
		node.ID,
		node.SessionID,
		node.Category,
		node.Content,
		vecStr,
		string(node.Provenance),
		node.TaintScore,
		metaJSON,
		node.CreatedAt.UnixNano(),
		node.UpdatedAt.UnixNano(),
		node.PrevHash,
		node.Hash,
		expiresAtNano,
	)

	return err
}

// RecallSemantic searches memories via cosine similarity against a query vector.
func (s *PostgresStore) RecallSemantic(ctx context.Context, queryVector []float32, filter brain.MemoryFilter) ([]*brain.SearchResult, error) {
	vecStr := FormatVector(queryVector)
	nowNano := time.Now().UnixNano()

	query := `
	SELECT id, session_id, category, content, vector_data::text, provenance, taint_score, metadata_json, created_at, updated_at, prev_hash, hash, expires_at,
	       1.0 - (vector_data <=> $1) AS score
	FROM memory_nodes
	WHERE (expires_at IS NULL OR expires_at > $2)
	`
	args := []interface{}{vecStr, nowNano}
	idx := 3

	if filter.SessionID != "" {
		query += fmt.Sprintf(" AND session_id = $%d", idx)
		args = append(args, filter.SessionID)
		idx++
	}
	if filter.Category != "" {
		query += fmt.Sprintf(" AND category = $%d", idx)
		args = append(args, filter.Category)
		idx++
	}
	if filter.Provenance != "" {
		query += fmt.Sprintf(" AND provenance = $%d", idx)
		args = append(args, string(filter.Provenance))
		idx++
	}

	query += fmt.Sprintf(" ORDER BY vector_data <=> $1 ASC LIMIT $%d", idx)
	limit := filter.Limit
	if limit <= 0 {
		limit = 10
	}
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []*brain.SearchResult
	for rows.Next() {
		var (
			id, sid, category, content, vecText, provStr, prevHash, hash string
			metaJSON                                                     []byte
			taintScore, score                                            float64
			createdAtNano, updatedAtNano                                 int64
			expiresAtNano                                                sql.NullInt64
		)

		if err := rows.Scan(&id, &sid, &category, &content, &vecText, &provStr, &taintScore, &metaJSON, &createdAtNano, &updatedAtNano, &prevHash, &hash, &expiresAtNano, &score); err != nil {
			return nil, err
		}

		if float32(score) < filter.MinScore {
			continue
		}

		var metadata map[string]string
		if len(metaJSON) > 0 {
			_ = json.Unmarshal(metaJSON, &metadata)
		}

		// Git repository and branch filtering if requested
		if filter.GitRepo != "" && (metadata == nil || metadata["git_repo"] != filter.GitRepo) {
			continue
		}
		if filter.GitBranch != "" && (metadata == nil || metadata["git_branch"] != filter.GitBranch) {
			continue
		}

		var expiresAt *time.Time
		if expiresAtNano.Valid {
			exp := time.Unix(0, expiresAtNano.Int64)
			expiresAt = &exp
		}

		parsedVec, _ := ParseVector(vecText)

		results = append(results, &brain.SearchResult{
			Node: &brain.MemoryNode{
				ID:         id,
				SessionID:  sid,
				Category:   category,
				Content:    content,
				Vector:     parsedVec,
				Provenance: brain.ProvenanceTier(provStr),
				TaintScore: taintScore,
				Metadata:   metadata,
				PrevHash:   prevHash,
				Hash:       hash,
				CreatedAt:  time.Unix(0, createdAtNano),
				UpdatedAt:  time.Unix(0, updatedAtNano),
				ExpiresAt:  expiresAt,
			},
			Score: float32(score),
		})
	}

	return results, rows.Err()
}

// RecallHybrid searches memories using combined PostgreSQL Full Text Search (tsvector) and vector similarity via RRF.
func (s *PostgresStore) RecallHybrid(ctx context.Context, query string, queryVector []float32, filter brain.MemoryFilter) ([]*brain.SearchResult, error) {
	// 1. Vector candidates
	vecFilter := filter
	vecFilter.Limit = 50
	vecResults, err := s.RecallSemantic(ctx, queryVector, vecFilter)
	if err != nil {
		return nil, err
	}

	vecRanks := make(map[string]int)
	nodesByID := make(map[string]*brain.MemoryNode)
	for i, r := range vecResults {
		vecRanks[r.Node.ID] = i
		nodesByID[r.Node.ID] = r.Node
	}

	// 2. Full text search
	ftsSQL := `
	SELECT id, session_id, category, content, vector_data::text, provenance, taint_score, metadata_json, created_at, updated_at, prev_hash, hash, expires_at
	FROM memory_nodes
	WHERE to_tsvector('english', content) @@ plainto_tsquery('english', $1)
	LIMIT 50;
	`
	ftsRanks := make(map[string]int)
	rows, err := s.db.QueryContext(ctx, ftsSQL, query)
	if err == nil {
		defer rows.Close()
		rankIdx := 0
		for rows.Next() {
			var (
				id, sid, category, content, vecText, provStr, prevHash, hash string
				metaJSON                                                     []byte
				taintScore                                                   float64
				createdAtNano, updatedAtNano                                 int64
				expiresAtNano                                                sql.NullInt64
			)
			if err := rows.Scan(&id, &sid, &category, &content, &vecText, &provStr, &taintScore, &metaJSON, &createdAtNano, &updatedAtNano, &prevHash, &hash, &expiresAtNano); err == nil {
				ftsRanks[id] = rankIdx
				rankIdx++
				if _, exists := nodesByID[id]; !exists {
					var metadata map[string]string
					if len(metaJSON) > 0 {
						_ = json.Unmarshal(metaJSON, &metadata)
					}
					var expiresAt *time.Time
					if expiresAtNano.Valid {
						exp := time.Unix(0, expiresAtNano.Int64)
						expiresAt = &exp
					}
					parsedVec, _ := ParseVector(vecText)
					nodesByID[id] = &brain.MemoryNode{
						ID:         id,
						SessionID:  sid,
						Category:   category,
						Content:    content,
						Vector:     parsedVec,
						Provenance: brain.ProvenanceTier(provStr),
						TaintScore: taintScore,
						Metadata:   metadata,
						PrevHash:   prevHash,
						Hash:       hash,
						CreatedAt:  time.Unix(0, createdAtNano),
						UpdatedAt:  time.Unix(0, updatedAtNano),
						ExpiresAt:  expiresAt,
					}
				}
			}
		}
	}

	// 3. Reciprocal Rank Fusion
	const k = 60.0
	nowNano := time.Now().UnixNano()
	var fusedResults []*brain.SearchResult

	for id, node := range nodesByID {
		if node.ExpiresAt != nil && node.ExpiresAt.UnixNano() < nowNano {
			continue
		}
		if filter.SessionID != "" && node.SessionID != filter.SessionID {
			continue
		}
		if filter.Category != "" && node.Category != filter.Category {
			continue
		}
		if filter.Provenance != "" && node.Provenance != filter.Provenance {
			continue
		}
		if filter.GitRepo != "" && (node.Metadata == nil || node.Metadata["git_repo"] != filter.GitRepo) {
			continue
		}
		if filter.GitBranch != "" && (node.Metadata == nil || node.Metadata["git_branch"] != filter.GitBranch) {
			continue
		}

		var score float32
		if rank, ok := vecRanks[id]; ok {
			score += float32(1.0 / (k + float64(rank)))
		}
		if rank, ok := ftsRanks[id]; ok {
			score += float32(1.0 / (k + float64(rank)))
		}

		fusedResults = append(fusedResults, &brain.SearchResult{
			Node:  node,
			Score: score,
		})
	}

	sort.Slice(fusedResults, func(i, j int) bool {
		return fusedResults[i].Score > fusedResults[j].Score
	})

	limit := filter.Limit
	if limit <= 0 {
		limit = 10
	}
	if len(fusedResults) > limit {
		fusedResults = fusedResults[:limit]
	}

	return fusedResults, nil
}

// RecallEpisodic retrieves chronological memories for a session.
func (s *PostgresStore) RecallEpisodic(ctx context.Context, sessionID string, limit int) ([]*brain.MemoryNode, error) {
	if limit <= 0 {
		limit = 20
	}
	query := `
	SELECT id, session_id, category, content, vector_data::text, provenance, taint_score, metadata_json, created_at, updated_at, prev_hash, hash, expires_at
	FROM memory_nodes
	WHERE session_id = $1
	ORDER BY created_at ASC
	LIMIT $2;
	`
	rows, err := s.db.QueryContext(ctx, query, sessionID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	nowNano := time.Now().UnixNano()
	var nodes []*brain.MemoryNode
	for rows.Next() {
		var (
			id, sid, category, content, vecText, provStr, prevHash, hash string
			metaJSON                                                     []byte
			taintScore                                                   float64
			createdAtNano, updatedAtNano                                 int64
			expiresAtNano                                                sql.NullInt64
		)
		if err := rows.Scan(&id, &sid, &category, &content, &vecText, &provStr, &taintScore, &metaJSON, &createdAtNano, &updatedAtNano, &prevHash, &hash, &expiresAtNano); err != nil {
			return nil, err
		}

		if expiresAtNano.Valid && expiresAtNano.Int64 < nowNano {
			continue
		}

		var metadata map[string]string
		if len(metaJSON) > 0 {
			_ = json.Unmarshal(metaJSON, &metadata)
		}

		var expiresAt *time.Time
		if expiresAtNano.Valid {
			exp := time.Unix(0, expiresAtNano.Int64)
			expiresAt = &exp
		}

		parsedVec, _ := ParseVector(vecText)

		nodes = append(nodes, &brain.MemoryNode{
			ID:         id,
			SessionID:  sid,
			Category:   category,
			Content:    content,
			Vector:     parsedVec,
			Provenance: brain.ProvenanceTier(provStr),
			TaintScore: taintScore,
			Metadata:   metadata,
			PrevHash:   prevHash,
			Hash:       hash,
			CreatedAt:  time.Unix(0, createdAtNano),
			UpdatedAt:  time.Unix(0, updatedAtNano),
			ExpiresAt:  expiresAt,
		})
	}

	return nodes, rows.Err()
}

// Delete removes a node by ID.
func (s *PostgresStore) Delete(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM memory_nodes WHERE id = $1", id)
	return err
}

// Count returns the count of memory nodes.
func (s *PostgresStore) Count(ctx context.Context, sessionPrefix string) (int, error) {
	var count int
	var err error
	if sessionPrefix == "" {
		err = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM memory_nodes").Scan(&count)
	} else {
		err = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM memory_nodes WHERE session_id LIKE $1", sessionPrefix+"%").Scan(&count)
	}
	return count, err
}

// PurgeExpired removes memories that have exceeded their designated TTL.
func (s *PostgresStore) PurgeExpired(ctx context.Context) (int, error) {
	nowNano := time.Now().UnixNano()
	res, err := s.db.ExecContext(ctx, "DELETE FROM memory_nodes WHERE expires_at IS NOT NULL AND expires_at < $1", nowNano)
	if err != nil {
		return 0, err
	}
	affected, _ := res.RowsAffected()
	return int(affected), nil
}

// Vacuum compacts tables and refreshes statistics.
func (s *PostgresStore) Vacuum(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, "VACUUM ANALYZE memory_nodes;")
	return err
}

// VerifySessionChain audits the cryptographic Merkle chain.
func (s *PostgresStore) VerifySessionChain(ctx context.Context, sessionID string) (bool, int, string, error) {
	nodes, err := s.RecallEpisodic(ctx, sessionID, 10000)
	if err != nil {
		return false, 0, "", err
	}

	var prevHash string
	for i, n := range nodes {
		if n.PrevHash != prevHash {
			return false, i, n.ID, fmt.Errorf("tamper detected at node %s: expected prev_hash %s, got %s", n.ID, prevHash, n.PrevHash)
		}
		expectedHash := ComputeNodeHash(n.PrevHash, n.ID, n.SessionID, n.Category, n.Content, n.CreatedAt.UnixNano())
		if n.Hash != expectedHash {
			return false, i, n.ID, fmt.Errorf("tamper detected at node %s: expected hash %s, stored hash %s", n.ID, expectedHash, n.Hash)
		}
		prevHash = n.Hash
	}

	return true, len(nodes), "", nil
}

// Close releases the database connection pool.
func (s *PostgresStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}
