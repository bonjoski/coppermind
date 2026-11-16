package sqlite

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/bonjoski/coppermind/pkg/authz"
	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/embedding"
	_ "modernc.org/sqlite"
)

const sqliteMemoryColumns = "id, session_id, category, content, vector_blob, provenance, taint_score, metadata_json, created_at, updated_at, prev_hash, hash, expires_at, derived, source_lens, parent_ids_json, severity, status, dedup_hash, authority_tier, lifecycle_status, author_identity, author_role, superseded_by_id, supersedes_id, rationale, advisory_ref"

type writeOpType int

const (
	opStore writeOpType = iota
	opDelete
	opSupersede
)

type supersedeReq struct {
	node           *brain.MemoryNode
	targetID       string
	rationale      string
	advisoryRef    string
	authorIdentity string
	authorRole     string
}

type writeRequest struct {
	op           writeOpType
	node         *brain.MemoryNode
	nodeID       string
	supersedeReq *supersedeReq
	errCh        chan error
}

// SQLiteStore implements brain.MemoryStore backed by pure-Go SQLite with WAL mode and a non-blocking write worker.
type SQLiteStore struct {
	db       *sql.DB
	writeCh  chan writeRequest
	stopCh   chan struct{}
	workerWg sync.WaitGroup
}

// NewSQLiteStore opens or initializes a SQLite database at dbPath.
func NewSQLiteStore(dbPath string) (*SQLiteStore, error) {
	dsn := fmt.Sprintf("%s?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	db.SetMaxOpenConns(16)
	db.SetMaxIdleConns(8)
	db.SetConnMaxLifetime(1 * time.Hour)

	if err := initSchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	store := &SQLiteStore{
		db:      db,
		writeCh: make(chan writeRequest, 512),
		stopCh:  make(chan struct{}),
	}

	store.workerWg.Add(1)
	go store.writeWorker()

	return store, nil
}

func initSchema(db *sql.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS memory_nodes (
		id TEXT PRIMARY KEY,
		session_id TEXT NOT NULL,
		category TEXT NOT NULL,
		content TEXT NOT NULL,
		vector_blob BLOB,
		provenance TEXT NOT NULL,
		taint_score REAL NOT NULL DEFAULT 0.0,
		metadata_json TEXT,
		created_at INTEGER NOT NULL,
		updated_at INTEGER NOT NULL,
		prev_hash TEXT NOT NULL DEFAULT '',
		hash TEXT NOT NULL DEFAULT '',
		expires_at INTEGER DEFAULT NULL,
		derived INTEGER NOT NULL DEFAULT 0,
		source_lens TEXT NOT NULL DEFAULT '',
		parent_ids_json TEXT NOT NULL DEFAULT '[]',
		severity TEXT NOT NULL DEFAULT '',
		status TEXT NOT NULL DEFAULT '',
		dedup_hash TEXT NOT NULL DEFAULT '',
		authority_tier TEXT NOT NULL DEFAULT 'TIER_3_EPISODIC',
		lifecycle_status TEXT NOT NULL DEFAULT 'ACTIVE',
		author_identity TEXT NOT NULL DEFAULT '',
		author_role TEXT NOT NULL DEFAULT '',
		superseded_by_id TEXT NOT NULL DEFAULT '',
		supersedes_id TEXT NOT NULL DEFAULT '',
		rationale TEXT NOT NULL DEFAULT '',
		advisory_ref TEXT NOT NULL DEFAULT ''
	);
	CREATE INDEX IF NOT EXISTS idx_memory_session ON memory_nodes(session_id);
	CREATE INDEX IF NOT EXISTS idx_memory_category ON memory_nodes(category);
	CREATE INDEX IF NOT EXISTS idx_memory_created_at ON memory_nodes(created_at);

	CREATE VIRTUAL TABLE IF NOT EXISTS memory_fts USING fts5(
		id UNINDEXED,
		session_id,
		category,
		content,
		tokenize = 'porter unicode61'
	);

	CREATE TABLE IF NOT EXISTS memory_supersessions (
		id TEXT PRIMARY KEY,
		superseding_id TEXT NOT NULL,
		superseded_id TEXT NOT NULL,
		rationale TEXT NOT NULL,
		advisory_ref TEXT NOT NULL DEFAULT '',
		author_identity TEXT NOT NULL DEFAULT '',
		author_role TEXT NOT NULL DEFAULT '',
		created_at INTEGER NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_supersessions_superseded ON memory_supersessions(superseded_id);
	CREATE INDEX IF NOT EXISTS idx_supersessions_superseding ON memory_supersessions(superseding_id);
	`
	if _, err := db.Exec(schema); err != nil {
		return err
	}

	// Migrations for existing databases
	_, _ = db.Exec("ALTER TABLE memory_nodes ADD COLUMN prev_hash TEXT NOT NULL DEFAULT ''")
	_, _ = db.Exec("ALTER TABLE memory_nodes ADD COLUMN hash TEXT NOT NULL DEFAULT ''")
	_, _ = db.Exec("ALTER TABLE memory_nodes ADD COLUMN expires_at INTEGER DEFAULT NULL")
	_, _ = db.Exec("ALTER TABLE memory_nodes ADD COLUMN derived INTEGER NOT NULL DEFAULT 0")
	_, _ = db.Exec("ALTER TABLE memory_nodes ADD COLUMN source_lens TEXT NOT NULL DEFAULT ''")
	_, _ = db.Exec("ALTER TABLE memory_nodes ADD COLUMN parent_ids_json TEXT NOT NULL DEFAULT '[]'")
	_, _ = db.Exec("ALTER TABLE memory_nodes ADD COLUMN severity TEXT NOT NULL DEFAULT ''")
	_, _ = db.Exec("ALTER TABLE memory_nodes ADD COLUMN status TEXT NOT NULL DEFAULT ''")
	_, _ = db.Exec("ALTER TABLE memory_nodes ADD COLUMN dedup_hash TEXT NOT NULL DEFAULT ''")
	_, _ = db.Exec("ALTER TABLE memory_nodes ADD COLUMN authority_tier TEXT NOT NULL DEFAULT 'TIER_3_EPISODIC'")
	_, _ = db.Exec("ALTER TABLE memory_nodes ADD COLUMN lifecycle_status TEXT NOT NULL DEFAULT 'ACTIVE'")
	_, _ = db.Exec("ALTER TABLE memory_nodes ADD COLUMN author_identity TEXT NOT NULL DEFAULT ''")
	_, _ = db.Exec("ALTER TABLE memory_nodes ADD COLUMN author_role TEXT NOT NULL DEFAULT ''")
	_, _ = db.Exec("ALTER TABLE memory_nodes ADD COLUMN superseded_by_id TEXT NOT NULL DEFAULT ''")
	_, _ = db.Exec("ALTER TABLE memory_nodes ADD COLUMN supersedes_id TEXT NOT NULL DEFAULT ''")
	_, _ = db.Exec("ALTER TABLE memory_nodes ADD COLUMN rationale TEXT NOT NULL DEFAULT ''")
	_, _ = db.Exec("ALTER TABLE memory_nodes ADD COLUMN advisory_ref TEXT NOT NULL DEFAULT ''")
	_, _ = db.Exec("CREATE INDEX IF NOT EXISTS idx_memory_expires_at ON memory_nodes(expires_at)")
	_, _ = db.Exec("CREATE INDEX IF NOT EXISTS idx_memory_derived ON memory_nodes(derived)")
	_, _ = db.Exec("CREATE INDEX IF NOT EXISTS idx_memory_source_lens ON memory_nodes(source_lens)")
	_, _ = db.Exec("CREATE INDEX IF NOT EXISTS idx_memory_dedup_hash ON memory_nodes(dedup_hash)")
	_, _ = db.Exec("CREATE INDEX IF NOT EXISTS idx_memory_severity_status ON memory_nodes(severity, status)")
	_, _ = db.Exec("CREATE INDEX IF NOT EXISTS idx_memory_authority_tier ON memory_nodes(authority_tier)")
	_, _ = db.Exec("CREATE INDEX IF NOT EXISTS idx_memory_lifecycle_status ON memory_nodes(lifecycle_status)")

	// Backfill FTS5 index if empty
	var ftsCount int
	_ = db.QueryRow("SELECT COUNT(*) FROM memory_fts").Scan(&ftsCount)
	if ftsCount == 0 {
		_, _ = db.Exec("INSERT OR IGNORE INTO memory_fts(id, session_id, category, content) SELECT id, session_id, category, content FROM memory_nodes")
	}

	return nil
}

func computeNodeHash(prevHash, id, sessionID, category, content string, createdAtNano int64) string {
	h := sha256.New()
	h.Write([]byte(prevHash))
	h.Write([]byte(":"))
	h.Write([]byte(id))
	h.Write([]byte(":"))
	h.Write([]byte(sessionID))
	h.Write([]byte(":"))
	h.Write([]byte(category))
	h.Write([]byte(":"))
	h.Write([]byte(content))
	h.Write([]byte(":"))
	h.Write([]byte(strconv.FormatInt(createdAtNano, 10)))
	return hex.EncodeToString(h.Sum(nil))
}

func (s *SQLiteStore) writeWorker() {
	defer s.workerWg.Done()
	for {
		select {
		case req := <-s.writeCh:
			var err error
			switch req.op {
			case opStore:
				err = s.execStore(req.node)
			case opDelete:
				err = s.execDelete(req.nodeID)
			case opSupersede:
				err = s.execSupersede(req.supersedeReq)
			}
			req.errCh <- err
		case <-s.stopCh:
			for len(s.writeCh) > 0 {
				req := <-s.writeCh
				var err error
				switch req.op {
				case opStore:
					err = s.execStore(req.node)
				case opDelete:
					err = s.execDelete(req.nodeID)
				case opSupersede:
					err = s.execSupersede(req.supersedeReq)
				}
				req.errCh <- err
			}
			return
		}
	}
}

func (s *SQLiteStore) storeNodeTx(tx *sql.Tx, node *brain.MemoryNode) error {
	vecBlob := encodeVector(node.Vector)
	metaJSON, _ := json.Marshal(node.Metadata)

	// Ensure Merkle hash chaining
	if node.Hash == "" {
		var prevHash string
		row := tx.QueryRow("SELECT hash FROM memory_nodes WHERE session_id = ? ORDER BY created_at DESC, rowid DESC LIMIT 1", node.SessionID)
		_ = row.Scan(&prevHash)
		if prevHash == "" {
			prevHash = "0000000000000000000000000000000000000000000000000000000000000000"
		}
		node.PrevHash = prevHash
		node.Hash = computeNodeHash(node.PrevHash, node.ID, node.SessionID, node.Category, node.Content, node.CreatedAt.UnixNano())
	}

	var expiresAtVal *int64
	if node.ExpiresAt != nil {
		exp := node.ExpiresAt.UnixNano()
		expiresAtVal = &exp
	}

	derivedInt := 0
	if node.Derived {
		derivedInt = 1
	}
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
		id, session_id, category, content, vector_blob, provenance, taint_score, metadata_json, created_at, updated_at, prev_hash, hash, expires_at,
		derived, source_lens, parent_ids_json, severity, status, dedup_hash,
		authority_tier, lifecycle_status, author_identity, author_role, superseded_by_id, supersedes_id, rationale, advisory_ref
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(id) DO UPDATE SET
		category=excluded.category,
		content=excluded.content,
		vector_blob=excluded.vector_blob,
		provenance=excluded.provenance,
		taint_score=excluded.taint_score,
		metadata_json=excluded.metadata_json,
		updated_at=excluded.updated_at,
		prev_hash=excluded.prev_hash,
		hash=excluded.hash,
		expires_at=excluded.expires_at,
		derived=excluded.derived,
		source_lens=excluded.source_lens,
		parent_ids_json=excluded.parent_ids_json,
		severity=excluded.severity,
		status=excluded.status,
		dedup_hash=excluded.dedup_hash,
		authority_tier=excluded.authority_tier,
		lifecycle_status=excluded.lifecycle_status,
		author_identity=excluded.author_identity,
		author_role=excluded.author_role,
		superseded_by_id=excluded.superseded_by_id,
		supersedes_id=excluded.supersedes_id,
		rationale=excluded.rationale,
		advisory_ref=excluded.advisory_ref;
	`
	_, err := tx.Exec(query,
		node.ID,
		node.SessionID,
		node.Category,
		node.Content,
		vecBlob,
		string(node.Provenance),
		node.TaintScore,
		string(metaJSON),
		node.CreatedAt.UnixNano(),
		node.UpdatedAt.UnixNano(),
		node.PrevHash,
		node.Hash,
		expiresAtVal,
		derivedInt,
		node.SourceLens,
		string(parentsJSON),
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
	if err != nil {
		return err
	}

	// Synchronize FTS5 virtual table
	_, _ = tx.Exec("DELETE FROM memory_fts WHERE id = ?", node.ID)
	_, err = tx.Exec("INSERT INTO memory_fts(id, session_id, category, content) VALUES (?, ?, ?, ?)",
		node.ID, node.SessionID, node.Category, node.Content)
	return err
}

func (s *SQLiteStore) execStore(node *brain.MemoryNode) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	if err := s.storeNodeTx(tx, node); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLiteStore) execSupersede(req *supersedeReq) error {
	if req.targetID == "" {
		return fmt.Errorf("target node ID cannot be empty")
	}
	if req.rationale == "" {
		return authz.ErrMissingRationale
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	var targetTier string
	row := tx.QueryRow("SELECT authority_tier FROM memory_nodes WHERE id = ?", req.targetID)
	if err := row.Scan(&targetTier); err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("target memory node %q not found: %w", req.targetID, err)
		}
		return fmt.Errorf("failed to query target memory node: %w", err)
	}

	targetTierParsed := authz.ParseAuthorityTier(targetTier)
	nodeTier := req.node.AuthorityTier
	if nodeTier == "" {
		nodeTier = authz.TierToString(authz.CategoryToDefaultTier(req.node.Category))
	}
	nodeTierParsed := authz.ParseAuthorityTier(nodeTier)
	if nodeTierParsed < targetTierParsed {
		return authz.ErrInvalidSupersession
	}

	nowNano := time.Now().UnixNano()
	_, err = tx.Exec(`
		UPDATE memory_nodes
		SET lifecycle_status = ?, superseded_by_id = ?, updated_at = ?
		WHERE id = ?
	`, string(authz.StatusSuperseded), req.node.ID, nowNano, req.targetID)
	if err != nil {
		return fmt.Errorf("failed to update target memory node: %w", err)
	}

	req.node.SupersedesID = req.targetID
	req.node.Rationale = req.rationale
	req.node.AdvisoryRef = req.advisoryRef
	req.node.AuthorIdentity = req.authorIdentity
	req.node.AuthorRole = req.authorRole
	req.node.LifecycleStatus = string(authz.StatusActive)
	if req.node.AuthorityTier == "" {
		req.node.AuthorityTier = targetTier
	}

	if err := s.storeNodeTx(tx, req.node); err != nil {
		return fmt.Errorf("failed to store superseding memory node: %w", err)
	}

	supersessionID := fmt.Sprintf("sup-%s-%s", req.node.ID, req.targetID)
	if len(supersessionID) > 64 {
		supersessionID = supersessionID[:64]
	}
	_, err = tx.Exec(`
		INSERT INTO memory_supersessions (
			id, superseding_id, superseded_id, rationale, advisory_ref, author_identity, author_role, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO NOTHING
	`, supersessionID, req.node.ID, req.targetID, req.rationale, req.advisoryRef, req.authorIdentity, req.authorRole, nowNano)
	if err != nil {
		return fmt.Errorf("failed to record memory supersession audit: %w", err)
	}

	return tx.Commit()
}

func scanNode(scanner interface {
	Scan(dest ...interface{}) error
}) (*brain.MemoryNode, error) {
	var (
		id, sessionID, category, content, provStr, metaJSON, prevHash, hash string
		vecBlob                                                             []byte
		taintScore                                                          float64
		createdAtNano, updatedAtNano                                        int64
		expiresAtNano                                                       sql.NullInt64
		derivedInt                                                          int
		sourceLens, parentIDsJSON, severity, status, dedupHash              string
		authorityTier, lifecycleStatus                                      sql.NullString
		authorIdentity, authorRole                                          sql.NullString
		supersededByID, supersedesID                                        sql.NullString
		rationale, advisoryRef                                              sql.NullString
	)

	err := scanner.Scan(
		&id, &sessionID, &category, &content, &vecBlob, &provStr, &taintScore, &metaJSON,
		&createdAtNano, &updatedAtNano, &prevHash, &hash, &expiresAtNano,
		&derivedInt, &sourceLens, &parentIDsJSON, &severity, &status, &dedupHash,
		&authorityTier, &lifecycleStatus, &authorIdentity, &authorRole,
		&supersededByID, &supersedesID, &rationale, &advisoryRef,
	)
	if err != nil {
		return nil, err
	}

	var metadata map[string]string
	if len(metaJSON) > 0 {
		_ = json.Unmarshal([]byte(metaJSON), &metadata)
	}

	var parentIDs []string
	if len(parentIDsJSON) > 0 {
		_ = json.Unmarshal([]byte(parentIDsJSON), &parentIDs)
	}

	var expiresAt *time.Time
	if expiresAtNano.Valid {
		exp := time.Unix(0, expiresAtNano.Int64)
		expiresAt = &exp
	}

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
		SessionID:       sessionID,
		Category:        category,
		Content:         content,
		Vector:          decodeVector(vecBlob),
		Provenance:      brain.ProvenanceTier(provStr),
		TaintScore:      taintScore,
		Metadata:        metadata,
		PrevHash:        prevHash,
		Hash:            hash,
		CreatedAt:       time.Unix(0, createdAtNano),
		UpdatedAt:       time.Unix(0, updatedAtNano),
		ExpiresAt:       expiresAt,
		Derived:         derivedInt == 1,
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

func (s *SQLiteStore) execDelete(nodeID string) error {
	_, _ = s.db.Exec("DELETE FROM memory_fts WHERE id = ?", nodeID)
	_, err := s.db.Exec("DELETE FROM memory_nodes WHERE id = ?", nodeID)
	return err
}

// Store queues a node for serialized write without blocking readers.
func (s *SQLiteStore) Store(ctx context.Context, node *brain.MemoryNode) error {
	if node.ID == "" {
		return fmt.Errorf("node ID cannot be empty")
	}
	if node.CreatedAt.IsZero() {
		node.CreatedAt = time.Now()
	}
	if node.UpdatedAt.IsZero() {
		node.UpdatedAt = time.Now()
	}

	errCh := make(chan error, 1)
	req := writeRequest{
		op:    opStore,
		node:  node,
		errCh: errCh,
	}

	select {
	case s.writeCh <- req:
		select {
		case err := <-errCh:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	case <-ctx.Done():
		return ctx.Err()
	case <-s.stopCh:
		return fmt.Errorf("store is closed")
	}
}

// Delete removes a node by ID.
func (s *SQLiteStore) Delete(ctx context.Context, id string) error {
	errCh := make(chan error, 1)
	req := writeRequest{
		op:     opDelete,
		nodeID: id,
		errCh:  errCh,
	}

	select {
	case s.writeCh <- req:
		select {
		case err := <-errCh:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	case <-ctx.Done():
		return ctx.Err()
	case <-s.stopCh:
		return fmt.Errorf("store is closed")
	}
}

// SupersessionRecord models an immutable audit entry when a memory node is superseded.
type SupersessionRecord struct {
	ID             string    `json:"id"`
	SupersedingID  string    `json:"superseding_id"`
	SupersededID   string    `json:"superseded_id"`
	Rationale      string    `json:"rationale"`
	AdvisoryRef    string    `json:"advisory_ref"`
	AuthorIdentity string    `json:"author_identity"`
	AuthorRole     string    `json:"author_role"`
	CreatedAt      time.Time `json:"created_at"`
}

// Supersede atomically persists a new memory node that supersedes an existing node in SQLite.
func (s *SQLiteStore) Supersede(
	ctx context.Context,
	supersedingNode *brain.MemoryNode,
	targetID string,
	rationale, advisoryRef string,
	authorIdentity, authorRole string,
) error {
	if supersedingNode.ID == "" {
		return fmt.Errorf("node ID cannot be empty")
	}
	if supersedingNode.CreatedAt.IsZero() {
		supersedingNode.CreatedAt = time.Now()
	}
	if supersedingNode.UpdatedAt.IsZero() {
		supersedingNode.UpdatedAt = time.Now()
	}

	errCh := make(chan error, 1)
	req := writeRequest{
		op: opSupersede,
		supersedeReq: &supersedeReq{
			node:           supersedingNode,
			targetID:       targetID,
			rationale:      rationale,
			advisoryRef:    advisoryRef,
			authorIdentity: authorIdentity,
			authorRole:     authorRole,
		},
		errCh: errCh,
	}

	select {
	case s.writeCh <- req:
		select {
		case err := <-errCh:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	case <-ctx.Done():
		return ctx.Err()
	case <-s.stopCh:
		return fmt.Errorf("store is closed")
	}
}

// GetAncestors traverses the supersession DAG backwards from startID.
func (s *SQLiteStore) GetAncestors(ctx context.Context, startID string) ([]*brain.MemoryNode, error) {
	var ancestors []*brain.MemoryNode
	currentID := startID
	visited := make(map[string]struct{})

	for currentID != "" {
		if _, seen := visited[currentID]; seen {
			break
		}
		visited[currentID] = struct{}{}

		node, err := s.getNodeByID(ctx, currentID)
		if err != nil {
			if err == sql.ErrNoRows {
				break
			}
			return nil, err
		}
		ancestors = append(ancestors, node)
		currentID = node.SupersedesID
	}

	return ancestors, nil
}

// GetAuditTrail retrieves all supersession events involving a given memory node ID.
func (s *SQLiteStore) GetAuditTrail(ctx context.Context, nodeID string) ([]*SupersessionRecord, error) {
	query := `
		SELECT id, superseding_id, superseded_id, rationale, advisory_ref, author_identity, author_role, created_at
		FROM memory_supersessions
		WHERE superseding_id = ? OR superseded_id = ?
		ORDER BY created_at ASC
	`
	rows, err := s.db.QueryContext(ctx, query, nodeID, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []*SupersessionRecord
	for rows.Next() {
		var (
			id, supersedingID, supersededID, rationale, advisoryRef, authorIdent, authorRole string
			createdAtNano                                                                    int64
		)
		if err := rows.Scan(&id, &supersedingID, &supersededID, &rationale, &advisoryRef, &authorIdent, &authorRole, &createdAtNano); err != nil {
			return nil, err
		}
		records = append(records, &SupersessionRecord{
			ID:             id,
			SupersedingID:  supersedingID,
			SupersededID:   supersededID,
			Rationale:      rationale,
			AdvisoryRef:    advisoryRef,
			AuthorIdentity: authorIdent,
			AuthorRole:     authorRole,
			CreatedAt:      time.Unix(0, createdAtNano),
		})
	}
	return records, rows.Err()
}

// RecallSemantic performs vector similarity search over stored memory nodes.
func (s *SQLiteStore) RecallSemantic(ctx context.Context, queryVector []float32, filter brain.MemoryFilter) ([]*brain.SearchResult, error) {
	query := "SELECT " + sqliteMemoryColumns + " FROM memory_nodes WHERE 1=1"
	var args []interface{}

	if filter.SessionID != "" {
		query += " AND session_id = ?"
		args = append(args, filter.SessionID)
	}
	if filter.Category != "" {
		query += " AND category = ?"
		args = append(args, filter.Category)
	}
	if filter.Provenance != "" {
		query += " AND provenance = ?"
		args = append(args, string(filter.Provenance))
	}
	if filter.Derived != nil {
		if *filter.Derived {
			query += " AND derived = 1"
		} else {
			query += " AND derived = 0"
		}
	}
	if filter.SourceLens != "" {
		query += " AND source_lens = ?"
		args = append(args, filter.SourceLens)
	}
	if filter.Severity != "" {
		query += " AND severity = ?"
		args = append(args, filter.Severity)
	}
	if filter.Status != "" {
		query += " AND status = ?"
		args = append(args, filter.Status)
	}

	// Epistemic Authority and Lifecycle Filters
	if !filter.IncludeSuperseded {
		if filter.LifecycleStatus != "" {
			query += " AND lifecycle_status = ?"
			args = append(args, filter.LifecycleStatus)
		} else {
			query += " AND (lifecycle_status = 'ACTIVE' OR lifecycle_status = '' OR lifecycle_status IS NULL)"
		}
	} else if filter.LifecycleStatus != "" {
		query += " AND lifecycle_status = ?"
		args = append(args, filter.LifecycleStatus)
	}
	if filter.AuthorityTier != "" {
		query += " AND authority_tier = ?"
		args = append(args, filter.AuthorityTier)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("semantic search query failed: %w", err)
	}
	defer rows.Close()

	var results []*brain.SearchResult
	nowNano := time.Now().UnixNano()

	for rows.Next() {
		node, err := scanNode(rows)
		if err != nil {
			return nil, err
		}

		// Filter out expired memories
		if node.ExpiresAt != nil && node.ExpiresAt.UnixNano() < nowNano {
			continue
		}

		score := embedding.CosineSimilarity(queryVector, node.Vector)
		if filter.MinScore > 0 && score < filter.MinScore {
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

		results = append(results, &brain.SearchResult{
			Node:  node,
			Score: score,
		})
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Score > results[j].Score
	})

	limit := filter.Limit
	if limit <= 0 {
		limit = 10
	}
	if len(results) > limit {
		results = results[:limit]
	}

	return results, nil
}

// RecallEpisodic retrieves chronological memories for a session.
func (s *SQLiteStore) RecallEpisodic(ctx context.Context, sessionID string, limit int) ([]*brain.MemoryNode, error) {
	if limit <= 0 {
		limit = 20
	}
	query := "SELECT " + sqliteMemoryColumns + " FROM memory_nodes WHERE session_id = ? ORDER BY created_at ASC LIMIT ?;"
	rows, err := s.db.QueryContext(ctx, query, sessionID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	nowNano := time.Now().UnixNano()
	var nodes []*brain.MemoryNode
	for rows.Next() {
		node, err := scanNode(rows)
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

// RecallHybrid combines SQLite FTS5 BM25 keyword retrieval with vector cosine similarity via Reciprocal Rank Fusion (RRF).
func (s *SQLiteStore) RecallHybrid(ctx context.Context, query string, queryVector []float32, filter brain.MemoryFilter) ([]*brain.SearchResult, error) {
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

	// 2. FTS5 BM25 search
	ftsQuery := sanitizeFTS5Query(query)
	bm25Ranks := make(map[string]int)
	if ftsQuery != "" {
		ftsSQL := "SELECT id FROM memory_fts WHERE memory_fts MATCH ? LIMIT 50"
		rows, err := s.db.QueryContext(ctx, ftsSQL, ftsQuery)
		if err == nil {
			defer rows.Close()
			rankIdx := 0
			for rows.Next() {
				var id string
				if err := rows.Scan(&id); err == nil {
					bm25Ranks[id] = rankIdx
					rankIdx++
					if _, exists := nodesByID[id]; !exists {
						node, err := s.getNodeByID(ctx, id)
						if err == nil && node != nil {
							nodesByID[id] = node
						}
					}
				}
			}
		}
	}

	// 3. Reciprocal Rank Fusion (RRF)
	const k = 60.0
	nowNano := time.Now().UnixNano()
	var fusedResults []*brain.SearchResult

	for id, node := range nodesByID {
		// Filter out expired memories
		if node.ExpiresAt != nil && node.ExpiresAt.UnixNano() < nowNano {
			continue
		}
		// Metadata and session filters
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

		// Epistemic Authority and Lifecycle Filters
		if !filter.IncludeSuperseded {
			if filter.LifecycleStatus != "" {
				if node.LifecycleStatus != filter.LifecycleStatus {
					continue
				}
			} else {
				if node.LifecycleStatus != "ACTIVE" && node.LifecycleStatus != "" {
					continue
				}
			}
		} else if filter.LifecycleStatus != "" {
			if node.LifecycleStatus != filter.LifecycleStatus {
				continue
			}
		}
		if filter.AuthorityTier != "" && node.AuthorityTier != filter.AuthorityTier {
			continue
		}

		var score float32
		if rank, ok := vecRanks[id]; ok {
			score += float32(1.0 / (k + float64(rank)))
		}
		if rank, ok := bm25Ranks[id]; ok {
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

func (s *SQLiteStore) getNodeByID(ctx context.Context, id string) (*brain.MemoryNode, error) {
	query := "SELECT " + sqliteMemoryColumns + " FROM memory_nodes WHERE id = ?"
	return scanNode(s.db.QueryRowContext(ctx, query, id))
}

// GetByID retrieves a memory node by its ID.
func (s *SQLiteStore) GetByID(ctx context.Context, id string) (*brain.MemoryNode, error) {
	return s.getNodeByID(ctx, id)
}

// GetByDedupHash retrieves an unresolved observation by its deterministic dedup hash.
func (s *SQLiteStore) GetByDedupHash(ctx context.Context, dedupHash string) (*brain.MemoryNode, error) {
	if dedupHash == "" {
		return nil, sql.ErrNoRows
	}
	query := "SELECT " + sqliteMemoryColumns + " FROM memory_nodes WHERE dedup_hash = ? AND status != 'resolved' LIMIT 1"
	return scanNode(s.db.QueryRowContext(ctx, query, dedupHash))
}

// GetObservationsForParents retrieves all active observations linked to the given parent memory IDs.
func (s *SQLiteStore) GetObservationsForParents(ctx context.Context, parentIDs []string) ([]*brain.MemoryNode, error) {
	if len(parentIDs) == 0 {
		return nil, nil
	}
	query := "SELECT " + sqliteMemoryColumns + " FROM memory_nodes WHERE derived = 1 AND status != 'resolved' ORDER BY created_at DESC"
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
		node, err := scanNode(rows)
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
func (s *SQLiteStore) ResolveObservation(ctx context.Context, id string) error {
	query := `UPDATE memory_nodes SET status = 'resolved', updated_at = ? WHERE id = ? AND derived = 1`
	_, err := s.db.ExecContext(ctx, query, time.Now().UnixNano(), id)
	return err
}

// ListObservations retrieves observations filtered by session, lens, status, and minSeverity.
func (s *SQLiteStore) ListObservations(ctx context.Context, sessionID string, lensName string, status string, minSeverity string, limit int) ([]*brain.MemoryNode, error) {
	if limit <= 0 {
		limit = 50
	}
	query := "SELECT " + sqliteMemoryColumns + " FROM memory_nodes WHERE derived = 1"
	var args []interface{}
	if sessionID != "" {
		query += " AND session_id = ?"
		args = append(args, sessionID)
	}
	if lensName != "" && lensName != "all" {
		query += " AND source_lens = ?"
		args = append(args, lensName)
	}
	if status != "" {
		query += " AND status = ?"
		args = append(args, status)
	}
	query += " ORDER BY created_at DESC LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var nodes []*brain.MemoryNode
	for rows.Next() {
		node, err := scanNode(rows)
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

// PurgeExpired removes memories that have exceeded their designated TTL.
func (s *SQLiteStore) PurgeExpired(ctx context.Context) (int, error) {
	nowNano := time.Now().UnixNano()
	rows, err := s.db.QueryContext(ctx, "SELECT id FROM memory_nodes WHERE expires_at IS NOT NULL AND expires_at < ?", nowNano)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil {
			ids = append(ids, id)
		}
	}

	for _, id := range ids {
		_ = s.Delete(ctx, id)
	}

	return len(ids), nil
}

// Vacuum compacts storage, checkpoints WAL, and reclaims disk space.
func (s *SQLiteStore) Vacuum(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, "PRAGMA wal_checkpoint(PASSIVE); VACUUM;")
	return err
}

func sanitizeFTS5Query(q string) string {
	var words []string
	var cur strings.Builder
	for _, r := range q {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			cur.WriteRune(r)
		} else {
			if cur.Len() > 0 {
				words = append(words, cur.String())
				cur.Reset()
			}
		}
	}
	if cur.Len() > 0 {
		words = append(words, cur.String())
	}

	if len(words) == 0 {
		return ""
	}

	var formatted []string
	for _, w := range words {
		formatted = append(formatted, fmt.Sprintf("%q*", w))
	}
	return strings.Join(formatted, " OR ")
}

// VerifySessionChain audits the cryptographic Merkle chain for a given session.
func (s *SQLiteStore) VerifySessionChain(ctx context.Context, sessionID string) (bool, int, string, error) {
	query := `
	SELECT id, session_id, category, content, created_at, prev_hash, hash
	FROM memory_nodes
	WHERE session_id = ?
	ORDER BY created_at ASC, rowid ASC;
	`
	rows, err := s.db.QueryContext(ctx, query, sessionID)
	if err != nil {
		return false, 0, "", err
	}
	defer rows.Close()

	expectedPrevHash := "0000000000000000000000000000000000000000000000000000000000000000"
	verifiedCount := 0

	for rows.Next() {
		var (
			id, sid, category, content, prevHash, storedHash string
			createdAtNano                                    int64
		)
		if err := rows.Scan(&id, &sid, &category, &content, &createdAtNano, &prevHash, &storedHash); err != nil {
			return false, verifiedCount, "", err
		}

		// Backward compatibility for pre-existing records prior to hashing
		if prevHash == "" && storedHash == "" {
			continue
		}

		if prevHash != expectedPrevHash {
			return false, verifiedCount, id, fmt.Errorf("cryptographic chain break at node %s: expected prev_hash %s, got %s", id, expectedPrevHash, prevHash)
		}

		computedHash := computeNodeHash(prevHash, id, sid, category, content, createdAtNano)
		if computedHash != storedHash {
			return false, verifiedCount, id, fmt.Errorf("tamper detected at node %s: expected hash %s, stored hash %s", id, computedHash, storedHash)
		}

		expectedPrevHash = storedHash
		verifiedCount++
	}

	return true, verifiedCount, "", rows.Err()
}

// Count returns the count of memory nodes.
func (s *SQLiteStore) Count(ctx context.Context, sessionPrefix string) (int, error) {
	query := "SELECT COUNT(*) FROM memory_nodes WHERE 1=1"
	var args []interface{}
	if sessionPrefix != "" {
		query += " AND session_id LIKE ?"
		args = append(args, sessionPrefix+"%")
	}

	var count int
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&count)
	return count, err
}

// Close gracefully stops the write worker and closes the database.
func (s *SQLiteStore) Close() error {
	close(s.stopCh)
	s.workerWg.Wait()
	return s.db.Close()
}

func encodeVector(vec []float32) []byte {
	if len(vec) == 0 {
		return nil
	}
	buf := new(bytes.Buffer)
	for _, v := range vec {
		bits := math.Float32bits(v)
		_ = binary.Write(buf, binary.LittleEndian, bits)
	}
	return buf.Bytes()
}

func decodeVector(b []byte) []float32 {
	if len(b) == 0 || len(b)%4 != 0 {
		return nil
	}
	count := len(b) / 4
	vec := make([]float32, count)
	for i := 0; i < count; i++ {
		bits := binary.LittleEndian.Uint32(b[i*4 : (i+1)*4])
		vec[i] = math.Float32frombits(bits)
	}
	return vec
}
