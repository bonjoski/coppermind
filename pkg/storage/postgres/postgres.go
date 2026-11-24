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

	"github.com/bonjoski/coppermind/pkg/authz"
	"github.com/bonjoski/coppermind/pkg/brain"
	_ "github.com/lib/pq"
)

const postgresMemoryColumns = `id, session_id, category, content, vector_data::text, provenance, taint_score, metadata_json, created_at, updated_at, prev_hash, hash, expires_at, derived, source_lens, parent_ids_json, severity, status, dedup_hash, authority_tier, lifecycle_status, author_identity, author_role, superseded_by_id, supersedes_id, rationale, advisory_ref`

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
		expires_at BIGINT,
		derived BOOLEAN NOT NULL DEFAULT FALSE,
		source_lens VARCHAR(64) DEFAULT '',
		parent_ids_json JSONB DEFAULT '[]'::jsonb,
		severity VARCHAR(32) DEFAULT '',
		status VARCHAR(32) DEFAULT '',
		dedup_hash VARCHAR(64) DEFAULT '',
		authority_tier VARCHAR(32) DEFAULT 'TIER_3_EPISODIC',
		lifecycle_status VARCHAR(32) DEFAULT 'ACTIVE',
		author_identity VARCHAR(256) DEFAULT '',
		author_role VARCHAR(64) DEFAULT '',
		superseded_by_id VARCHAR(64) DEFAULT '',
		supersedes_id VARCHAR(64) DEFAULT '',
		rationale TEXT DEFAULT '',
		advisory_ref VARCHAR(128) DEFAULT ''
	);

	-- Run ALTER TABLE statements FIRST so that missing columns on existing tables are added before indices
	ALTER TABLE memory_nodes ADD COLUMN IF NOT EXISTS derived BOOLEAN NOT NULL DEFAULT FALSE;
	ALTER TABLE memory_nodes ADD COLUMN IF NOT EXISTS source_lens VARCHAR(64) DEFAULT '';
	ALTER TABLE memory_nodes ADD COLUMN IF NOT EXISTS parent_ids_json JSONB DEFAULT '[]'::jsonb;
	ALTER TABLE memory_nodes ADD COLUMN IF NOT EXISTS severity VARCHAR(32) DEFAULT '';
	ALTER TABLE memory_nodes ADD COLUMN IF NOT EXISTS status VARCHAR(32) DEFAULT '';
	ALTER TABLE memory_nodes ADD COLUMN IF NOT EXISTS dedup_hash VARCHAR(64) DEFAULT '';
	ALTER TABLE memory_nodes ADD COLUMN IF NOT EXISTS authority_tier VARCHAR(32) DEFAULT 'TIER_3_EPISODIC';
	ALTER TABLE memory_nodes ADD COLUMN IF NOT EXISTS lifecycle_status VARCHAR(32) DEFAULT 'ACTIVE';
	ALTER TABLE memory_nodes ADD COLUMN IF NOT EXISTS author_identity VARCHAR(256) DEFAULT '';
	ALTER TABLE memory_nodes ADD COLUMN IF NOT EXISTS author_role VARCHAR(64) DEFAULT '';
	ALTER TABLE memory_nodes ADD COLUMN IF NOT EXISTS superseded_by_id VARCHAR(64) DEFAULT '';
	ALTER TABLE memory_nodes ADD COLUMN IF NOT EXISTS supersedes_id VARCHAR(64) DEFAULT '';
	ALTER TABLE memory_nodes ADD COLUMN IF NOT EXISTS rationale TEXT DEFAULT '';
	ALTER TABLE memory_nodes ADD COLUMN IF NOT EXISTS advisory_ref VARCHAR(128) DEFAULT '';

	CREATE INDEX IF NOT EXISTS idx_pg_session_id ON memory_nodes(session_id);
	CREATE INDEX IF NOT EXISTS idx_pg_category ON memory_nodes(category);
	CREATE INDEX IF NOT EXISTS idx_pg_created_at ON memory_nodes(created_at);
	CREATE INDEX IF NOT EXISTS idx_pg_expires_at ON memory_nodes(expires_at);
	CREATE INDEX IF NOT EXISTS idx_pg_derived ON memory_nodes(derived);
	CREATE INDEX IF NOT EXISTS idx_pg_source_lens ON memory_nodes(source_lens);
	CREATE INDEX IF NOT EXISTS idx_pg_dedup_hash ON memory_nodes(dedup_hash);
	CREATE INDEX IF NOT EXISTS idx_pg_severity_status ON memory_nodes(severity, status);
	CREATE INDEX IF NOT EXISTS idx_pg_authority_tier ON memory_nodes(authority_tier);
	CREATE INDEX IF NOT EXISTS idx_pg_lifecycle_status ON memory_nodes(lifecycle_status);
	CREATE INDEX IF NOT EXISTS idx_pg_superseded_by ON memory_nodes(superseded_by_id);
	CREATE INDEX IF NOT EXISTS idx_pg_content_fts ON memory_nodes USING gin(to_tsvector('english', content));

	CREATE TABLE IF NOT EXISTS memory_supersessions (
		id VARCHAR(64) PRIMARY KEY,
		superseding_id VARCHAR(64) NOT NULL,
		superseded_id VARCHAR(64) NOT NULL,
		rationale TEXT NOT NULL,
		advisory_ref VARCHAR(128) DEFAULT '',
		author_identity VARCHAR(256) DEFAULT '',
		author_role VARCHAR(64) DEFAULT '',
		created_at BIGINT NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_pg_supersessions_superseded ON memory_supersessions(superseded_id);
	CREATE INDEX IF NOT EXISTS idx_pg_supersessions_superseding ON memory_supersessions(superseding_id);
	`, s.dimension)

	_, err := s.db.ExecContext(ctx, schema)
	if err != nil {
		return err
	}

	// Backfill authority_tier from CategoryToDefaultTier for existing rows with default tier
	archCategories := []string{"architecture", "convention", "tech_stack", "api_schema", "decision", "accepted-rfc", "ecosystem-architecture", "rfc", "adr", "learning", "architectural-learning", "lesson", "learnings"}
	for _, cat := range archCategories {
		_, _ = s.db.ExecContext(ctx, "UPDATE memory_nodes SET authority_tier = 'TIER_1_ARCHITECTURE' WHERE category = $1 AND authority_tier = 'TIER_3_EPISODIC'", cat)
	}
	sovereignCategories := []string{"security_policy", "sandbox_rule", "crypto_root", "sovereign_invariant"}
	for _, cat := range sovereignCategories {
		_, _ = s.db.ExecContext(ctx, "UPDATE memory_nodes SET authority_tier = 'TIER_0_SOVEREIGN' WHERE category = $1 AND authority_tier = 'TIER_3_EPISODIC'", cat)
	}
	productCategories := []string{"product", "user_story", "acceptance_criteria", "spec", "business_logic"}
	for _, cat := range productCategories {
		_, _ = s.db.ExecContext(ctx, "UPDATE memory_nodes SET authority_tier = 'TIER_2_PRODUCT' WHERE category = $1 AND authority_tier = 'TIER_3_EPISODIC'", cat)
	}

	return nil
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

	parentsJSON, _ := json.Marshal(node.ParentIDs)
	if node.ParentIDs == nil {
		parentsJSON = []byte("[]")
	}

	authorityTier := node.AuthorityTier
	if authorityTier == "" {
		authorityTier = authz.TierToString(authz.CategoryToDefaultTier(node.Category))
	}
	lifecycleStatus := node.LifecycleStatus
	if lifecycleStatus == "" {
		lifecycleStatus = string(authz.StatusActive)
	}
	node.AuthorityTier = authorityTier
	node.LifecycleStatus = lifecycleStatus

	query := `
	INSERT INTO memory_nodes (
		id, session_id, category, content, vector_data, provenance, taint_score, metadata_json, created_at, updated_at, prev_hash, hash, expires_at,
		derived, source_lens, parent_ids_json, severity, status, dedup_hash,
		authority_tier, lifecycle_status, author_identity, author_role, superseded_by_id, supersedes_id, rationale, advisory_ref
	) VALUES (
		$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19,
		$20, $21, $22, $23, $24, $25, $26, $27
	)
	ON CONFLICT (id) DO UPDATE SET
		category = EXCLUDED.category,
		content = EXCLUDED.content,
		vector_data = EXCLUDED.vector_data,
		provenance = EXCLUDED.provenance,
		taint_score = EXCLUDED.taint_score,
		metadata_json = EXCLUDED.metadata_json,
		updated_at = EXCLUDED.updated_at,
		expires_at = EXCLUDED.expires_at,
		derived = EXCLUDED.derived,
		source_lens = EXCLUDED.source_lens,
		parent_ids_json = EXCLUDED.parent_ids_json,
		severity = EXCLUDED.severity,
		status = EXCLUDED.status,
		dedup_hash = EXCLUDED.dedup_hash,
		authority_tier = EXCLUDED.authority_tier,
		lifecycle_status = EXCLUDED.lifecycle_status,
		author_identity = EXCLUDED.author_identity,
		author_role = EXCLUDED.author_role,
		superseded_by_id = EXCLUDED.superseded_by_id,
		supersedes_id = EXCLUDED.supersedes_id,
		rationale = EXCLUDED.rationale,
		advisory_ref = EXCLUDED.advisory_ref;
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
		node.Derived,
		node.SourceLens,
		parentsJSON,
		node.Severity,
		node.Status,
		node.DedupHash,
		authorityTier,
		lifecycleStatus,
		node.AuthorIdentity,
		node.AuthorRole,
		node.SupersededByID,
		node.SupersedesID,
		node.Rationale,
		node.AdvisoryRef,
	)

	return err
}

func scanPostgresNode(scanner interface {
	Scan(dest ...interface{}) error
}, scoreDest *float32) (*brain.MemoryNode, error) {
	var (
		id, sid, category, content, vecText, provStr, prevHash, hash string
		metaJSON, parentIDsJSON                                      []byte
		taintScore                                                   float64
		createdAtNano, updatedAtNano                                 int64
		expiresAtNano                                                sql.NullInt64
		derived                                                      bool
		sourceLens, severity, status, dedupHash                      string
		authorityTier, lifecycleStatus                               sql.NullString
		authorIdentity, authorRole                                   sql.NullString
		supersededByID, supersedesID                                 sql.NullString
		rationale, advisoryRef                                       sql.NullString
	)

	dests := []interface{}{
		&id, &sid, &category, &content, &vecText, &provStr, &taintScore, &metaJSON,
		&createdAtNano, &updatedAtNano, &prevHash, &hash, &expiresAtNano,
		&derived, &sourceLens, &parentIDsJSON, &severity, &status, &dedupHash,
		&authorityTier, &lifecycleStatus, &authorIdentity, &authorRole,
		&supersededByID, &supersedesID, &rationale, &advisoryRef,
	}
	if scoreDest != nil {
		dests = append(dests, scoreDest)
	}

	err := scanner.Scan(dests...)
	if err != nil {
		return nil, err
	}

	var metadata map[string]string
	if len(metaJSON) > 0 {
		_ = json.Unmarshal(metaJSON, &metadata)
	}

	var parentIDs []string
	if len(parentIDsJSON) > 0 {
		_ = json.Unmarshal(parentIDsJSON, &parentIDs)
	}

	var expiresAt *time.Time
	if expiresAtNano.Valid {
		exp := time.Unix(0, expiresAtNano.Int64)
		expiresAt = &exp
	}

	parsedVec, _ := ParseVector(vecText)

	tierVal := authorityTier.String
	if tierVal == "" {
		tierVal = authz.TierToString(authz.CategoryToDefaultTier(category))
	}
	statusVal := lifecycleStatus.String
	if statusVal == "" {
		statusVal = string(authz.StatusActive)
	}

	return &brain.MemoryNode{
		ID:              id,
		SessionID:       sid,
		Category:        category,
		Content:         content,
		Vector:          parsedVec,
		Provenance:      brain.ProvenanceTier(provStr),
		TaintScore:      taintScore,
		Metadata:        metadata,
		PrevHash:        prevHash,
		Hash:            hash,
		CreatedAt:       time.Unix(0, createdAtNano),
		UpdatedAt:       time.Unix(0, updatedAtNano),
		ExpiresAt:       expiresAt,
		Derived:         derived,
		SourceLens:      sourceLens,
		ParentIDs:       parentIDs,
		Severity:        severity,
		Status:          status,
		DedupHash:       dedupHash,
		AuthorityTier:   tierVal,
		LifecycleStatus: statusVal,
		AuthorIdentity:  authorIdentity.String,
		AuthorRole:      authorRole.String,
		SupersededByID:  supersededByID.String,
		SupersedesID:    supersedesID.String,
		Rationale:       rationale.String,
		AdvisoryRef:     advisoryRef.String,
	}, nil
}

// RecallSemantic searches memories via cosine similarity against a query vector.
func (s *PostgresStore) RecallSemantic(ctx context.Context, queryVector []float32, filter brain.MemoryFilter) ([]*brain.SearchResult, error) {
	vecStr := FormatVector(queryVector)
	nowNano := time.Now().UnixNano()

	query := fmt.Sprintf(`
	SELECT %s,
	       1.0 - (vector_data <=> $1) AS score
	FROM memory_nodes
	WHERE (expires_at IS NULL OR expires_at > $2)
	`, postgresMemoryColumns)
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
	if filter.Derived != nil {
		query += fmt.Sprintf(" AND derived = $%d", idx)
		args = append(args, *filter.Derived)
		idx++
	}
	if filter.SourceLens != "" {
		query += fmt.Sprintf(" AND source_lens = $%d", idx)
		args = append(args, filter.SourceLens)
		idx++
	}
	if filter.Severity != "" {
		query += fmt.Sprintf(" AND severity = $%d", idx)
		args = append(args, filter.Severity)
		idx++
	}
	if filter.Status != "" {
		query += fmt.Sprintf(" AND status = $%d", idx)
		args = append(args, filter.Status)
		idx++
	}

	if !filter.IncludeSuperseded {
		if filter.LifecycleStatus != "" {
			query += fmt.Sprintf(" AND lifecycle_status = $%d", idx)
			args = append(args, filter.LifecycleStatus)
			idx++
		} else {
			query += " AND (lifecycle_status = 'ACTIVE' OR lifecycle_status = '' OR lifecycle_status IS NULL)"
		}
	} else if filter.LifecycleStatus != "" {
		query += fmt.Sprintf(" AND lifecycle_status = $%d", idx)
		args = append(args, filter.LifecycleStatus)
		idx++
	}

	if filter.AuthorityTier != "" {
		query += fmt.Sprintf(" AND authority_tier = $%d", idx)
		args = append(args, filter.AuthorityTier)
		idx++
	}
	if filter.CreatedAfter != nil {
		query += fmt.Sprintf(" AND created_at >= $%d", idx)
		args = append(args, filter.CreatedAfter.UnixNano())
		idx++
	}
	if filter.CreatedBefore != nil {
		query += fmt.Sprintf(" AND created_at <= $%d", idx)
		args = append(args, filter.CreatedBefore.UnixNano())
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
		var score float32
		node, err := scanPostgresNode(rows, &score)
		if err != nil {
			return nil, err
		}

		if score < filter.MinScore {
			continue
		}

		// Git repository and branch filtering if requested
		if filter.GitRepo != "" && (node.Metadata == nil || node.Metadata["git_repo"] != filter.GitRepo) {
			continue
		}
		if filter.GitBranch != "" && (node.Metadata == nil || node.Metadata["git_branch"] != filter.GitBranch) {
			continue
		}

		// Filter by parent ID if requested
		if filter.ParentID != "" {
			matches := false
			for _, pid := range node.ParentIDs {
				if pid == filter.ParentID {
					matches = true
					break
				}
			}
			if !matches {
				continue
			}
		}

		if !filter.IncludeSuperseded {
			if filter.LifecycleStatus != "" {
				if !strings.EqualFold(node.LifecycleStatus, filter.LifecycleStatus) {
					continue
				}
			} else if node.LifecycleStatus != "" && !strings.EqualFold(node.LifecycleStatus, "ACTIVE") {
				continue
			}
		} else if filter.LifecycleStatus != "" && !strings.EqualFold(node.LifecycleStatus, filter.LifecycleStatus) {
			continue
		}

		if filter.AuthorityTier != "" && !strings.EqualFold(node.AuthorityTier, filter.AuthorityTier) {
			continue
		}

		results = append(results, &brain.SearchResult{
			Node:  node,
			Score: score,
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
	ftsSQL := fmt.Sprintf(`
	SELECT %s
	FROM memory_nodes
	WHERE to_tsvector('english', content) @@ plainto_tsquery('english', $1)
	LIMIT 50;
	`, postgresMemoryColumns)
	ftsRanks := make(map[string]int)
	rows, err := s.db.QueryContext(ctx, ftsSQL, query)
	if err == nil {
		defer rows.Close()
		rankIdx := 0
		for rows.Next() {
			node, err := scanPostgresNode(rows, nil)
			if err == nil {
				ftsRanks[node.ID] = rankIdx
				rankIdx++
				if _, exists := nodesByID[node.ID]; !exists {
					nodesByID[node.ID] = node
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
		if filter.Derived != nil && node.Derived != *filter.Derived {
			continue
		}
		if filter.SourceLens != "" && node.SourceLens != filter.SourceLens {
			continue
		}
		if filter.Severity != "" && !strings.EqualFold(node.Severity, filter.Severity) {
			continue
		}
		if filter.Status != "" && !strings.EqualFold(node.Status, filter.Status) {
			continue
		}
		if filter.ParentID != "" {
			matches := false
			for _, pid := range node.ParentIDs {
				if pid == filter.ParentID {
					matches = true
					break
				}
			}
			if !matches {
				continue
			}
		}

		if !filter.IncludeSuperseded {
			if filter.LifecycleStatus != "" {
				if !strings.EqualFold(node.LifecycleStatus, filter.LifecycleStatus) {
					continue
				}
			} else if node.LifecycleStatus != "" && !strings.EqualFold(node.LifecycleStatus, "ACTIVE") {
				continue
			}
		} else if filter.LifecycleStatus != "" && !strings.EqualFold(node.LifecycleStatus, filter.LifecycleStatus) {
			continue
		}

		if filter.AuthorityTier != "" && !strings.EqualFold(node.AuthorityTier, filter.AuthorityTier) {
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
	query := fmt.Sprintf(`
	SELECT %s
	FROM memory_nodes
	WHERE session_id = $1
	ORDER BY created_at ASC
	LIMIT $2;
	`, postgresMemoryColumns)
	rows, err := s.db.QueryContext(ctx, query, sessionID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	nowNano := time.Now().UnixNano()
	var nodes []*brain.MemoryNode
	for rows.Next() {
		node, err := scanPostgresNode(rows, nil)
		if err != nil {
			return nil, err
		}
		if node.ExpiresAt != nil && node.ExpiresAt.UnixNano() < nowNano {
			continue
		}
		nodes = append(nodes, node)
	}

	return nodes, rows.Err()
}

// GetByID retrieves a memory node by its ID.
func (s *PostgresStore) GetByID(ctx context.Context, id string) (*brain.MemoryNode, error) {
	query := fmt.Sprintf(`
	SELECT %s
	FROM memory_nodes WHERE id = $1
	`, postgresMemoryColumns)
	return scanPostgresNode(s.db.QueryRowContext(ctx, query, id), nil)
}

// GetByDedupHash retrieves an unresolved observation by its deterministic dedup hash.
func (s *PostgresStore) GetByDedupHash(ctx context.Context, dedupHash string) (*brain.MemoryNode, error) {
	if dedupHash == "" {
		return nil, sql.ErrNoRows
	}
	query := fmt.Sprintf(`
	SELECT %s
	FROM memory_nodes
	WHERE dedup_hash = $1 AND status != 'resolved'
	LIMIT 1
	`, postgresMemoryColumns)
	return scanPostgresNode(s.db.QueryRowContext(ctx, query, dedupHash), nil)
}

// GetObservationsForParents retrieves all active observations linked to the given parent memory IDs.
func (s *PostgresStore) GetObservationsForParents(ctx context.Context, parentIDs []string) ([]*brain.MemoryNode, error) {
	if len(parentIDs) == 0 {
		return nil, nil
	}
	query := fmt.Sprintf(`
	SELECT %s
	FROM memory_nodes
	WHERE derived = TRUE AND (status != 'resolved' OR source_lens = 'synthesizer')
	ORDER BY created_at DESC
	`, postgresMemoryColumns)
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	parentSet := make(map[string]struct{}, len(parentIDs))
	for _, pid := range parentIDs {
		parentSet[pid] = struct{}{}
	}

	var results []*brain.MemoryNode
	for rows.Next() {
		node, err := scanPostgresNode(rows, nil)
		if err != nil {
			return nil, err
		}
		matches := false
		for _, pid := range node.ParentIDs {
			if _, ok := parentSet[pid]; ok {
				matches = true
				break
			}
		}
		if matches {
			results = append(results, node)
		}
	}
	return results, rows.Err()
}

// ResolveObservation marks an observation as resolved.
func (s *PostgresStore) ResolveObservation(ctx context.Context, id string) error {
	query := `UPDATE memory_nodes SET status = 'resolved', updated_at = $1 WHERE id = $2 AND derived = TRUE`
	_, err := s.db.ExecContext(ctx, query, time.Now().UnixNano(), id)
	return err
}

// ListObservations retrieves observations filtered by session, lens, status, and minSeverity.
func (s *PostgresStore) ListObservations(ctx context.Context, sessionID string, lensName string, status string, minSeverity string, limit int) ([]*brain.MemoryNode, error) {
	if limit <= 0 {
		limit = 50
	}
	query := fmt.Sprintf(`
	SELECT %s
	FROM memory_nodes
	WHERE derived = TRUE
	`, postgresMemoryColumns)
	var args []interface{}
	idx := 1
	if sessionID != "" {
		query += fmt.Sprintf(" AND session_id = $%d", idx)
		args = append(args, sessionID)
		idx++
	}
	if lensName != "" && lensName != "all" {
		query += fmt.Sprintf(" AND source_lens = $%d", idx)
		args = append(args, lensName)
		idx++
	}
	if status != "" {
		query += fmt.Sprintf(" AND status = $%d", idx)
		args = append(args, status)
		idx++
	}
	query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d", idx)
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var nodes []*brain.MemoryNode
	for rows.Next() {
		node, err := scanPostgresNode(rows, nil)
		if err != nil {
			return nil, err
		}
		if minSeverity != "" && !severityGTE(node.Severity, minSeverity) {
			continue
		}
		nodes = append(nodes, node)
	}
	return nodes, rows.Err()
}

func severityGTE(a, b string) bool {
	rank := map[string]int{
		"info":     1,
		"low":      2,
		"medium":   3,
		"high":     4,
		"critical": 5,
	}
	ra := rank[strings.ToLower(a)]
	rb := rank[strings.ToLower(b)]
	return ra >= rb
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
