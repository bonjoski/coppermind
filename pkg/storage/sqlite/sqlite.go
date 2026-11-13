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

	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/embedding"
	_ "modernc.org/sqlite"
)

type writeOpType int

const (
	opStore writeOpType = iota
	opDelete
)

type writeRequest struct {
	op     writeOpType
	node   *brain.MemoryNode
	nodeID string
	errCh  chan error
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
		expires_at INTEGER DEFAULT NULL
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
	`
	if _, err := db.Exec(schema); err != nil {
		return err
	}

	// Migrations for existing databases
	_, _ = db.Exec("ALTER TABLE memory_nodes ADD COLUMN prev_hash TEXT NOT NULL DEFAULT ''")
	_, _ = db.Exec("ALTER TABLE memory_nodes ADD COLUMN hash TEXT NOT NULL DEFAULT ''")
	_, _ = db.Exec("ALTER TABLE memory_nodes ADD COLUMN expires_at INTEGER DEFAULT NULL")
	_, _ = db.Exec("CREATE INDEX IF NOT EXISTS idx_memory_expires_at ON memory_nodes(expires_at)")

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
				}
				req.errCh <- err
			}
			return
		}
	}
}

func (s *SQLiteStore) execStore(node *brain.MemoryNode) error {
	vecBlob := encodeVector(node.Vector)
	metaJSON, _ := json.Marshal(node.Metadata)

	// Ensure Merkle hash chaining
	if node.Hash == "" {
		var prevHash string
		row := s.db.QueryRow("SELECT hash FROM memory_nodes WHERE session_id = ? ORDER BY created_at DESC, rowid DESC LIMIT 1", node.SessionID)
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

	query := `
	INSERT INTO memory_nodes (
		id, session_id, category, content, vector_blob, provenance, taint_score, metadata_json, created_at, updated_at, prev_hash, hash, expires_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
		expires_at=excluded.expires_at;
	`
	_, err := s.db.Exec(query,
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
	)
	if err != nil {
		return err
	}

	// Synchronize FTS5 virtual table
	_, _ = s.db.Exec("DELETE FROM memory_fts WHERE id = ?", node.ID)
	_, err = s.db.Exec("INSERT INTO memory_fts(id, session_id, category, content) VALUES (?, ?, ?, ?)",
		node.ID, node.SessionID, node.Category, node.Content)
	return err
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

// RecallSemantic performs vector similarity search over stored memory nodes.
func (s *SQLiteStore) RecallSemantic(ctx context.Context, queryVector []float32, filter brain.MemoryFilter) ([]*brain.SearchResult, error) {
	query := `SELECT id, session_id, category, content, vector_blob, provenance, taint_score, metadata_json, created_at, updated_at, prev_hash, hash, expires_at FROM memory_nodes WHERE 1=1`
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

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("semantic search query failed: %w", err)
	}
	defer rows.Close()

	var results []*brain.SearchResult
	nowNano := time.Now().UnixNano()

	for rows.Next() {
		var (
			id, sessionID, category, content, provStr, metaJSON, prevHash, hash string
			vecBlob                                                             []byte
			taintScore                                                          float64
			createdAtNano, updatedAtNano                                        int64
			expiresAtNano                                                       sql.NullInt64
		)

		if err := rows.Scan(&id, &sessionID, &category, &content, &vecBlob, &provStr, &taintScore, &metaJSON, &createdAtNano, &updatedAtNano, &prevHash, &hash, &expiresAtNano); err != nil {
			return nil, err
		}

		// Filter out expired memories
		if expiresAtNano.Valid && expiresAtNano.Int64 < nowNano {
			continue
		}

		nodeVec := decodeVector(vecBlob)
		score := embedding.CosineSimilarity(queryVector, nodeVec)

		if filter.MinScore > 0 && score < filter.MinScore {
			continue
		}

		var metadata map[string]string
		if len(metaJSON) > 0 {
			_ = json.Unmarshal([]byte(metaJSON), &metadata)
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

		node := &brain.MemoryNode{
			ID:         id,
			SessionID:  sessionID,
			Category:   category,
			Content:    content,
			Vector:     nodeVec,
			Provenance: brain.ProvenanceTier(provStr),
			TaintScore: taintScore,
			Metadata:   metadata,
			PrevHash:   prevHash,
			Hash:       hash,
			CreatedAt:  time.Unix(0, createdAtNano),
			UpdatedAt:  time.Unix(0, updatedAtNano),
			ExpiresAt:  expiresAt,
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
	query := `
	SELECT id, session_id, category, content, vector_blob, provenance, taint_score, metadata_json, created_at, updated_at, prev_hash, hash, expires_at
	FROM memory_nodes
	WHERE session_id = ?
	ORDER BY created_at ASC
	LIMIT ?;
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
			id, sid, category, content, provStr, metaJSON, prevHash, hash string
			vecBlob                                                       []byte
			taintScore                                                    float64
			createdAtNano, updatedAtNano                                  int64
			expiresAtNano                                                 sql.NullInt64
		)
		if err := rows.Scan(&id, &sid, &category, &content, &vecBlob, &provStr, &taintScore, &metaJSON, &createdAtNano, &updatedAtNano, &prevHash, &hash, &expiresAtNano); err != nil {
			return nil, err
		}

		if expiresAtNano.Valid && expiresAtNano.Int64 < nowNano {
			continue
		}

		var metadata map[string]string
		if len(metaJSON) > 0 {
			_ = json.Unmarshal([]byte(metaJSON), &metadata)
		}

		var expiresAt *time.Time
		if expiresAtNano.Valid {
			exp := time.Unix(0, expiresAtNano.Int64)
			expiresAt = &exp
		}

		nodes = append(nodes, &brain.MemoryNode{
			ID:         id,
			SessionID:  sid,
			Category:   category,
			Content:    content,
			Vector:     decodeVector(vecBlob),
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
	query := `
	SELECT id, session_id, category, content, vector_blob, provenance, taint_score, metadata_json, created_at, updated_at, prev_hash, hash, expires_at
	FROM memory_nodes WHERE id = ?
	`
	var (
		nodeID, sid, cat, content, provStr, metaJSON, prevHash, hash string
		vecBlob                                                      []byte
		taintScore                                                   float64
		createdNano, updatedNano                                     int64
		expiresAtNano                                                sql.NullInt64
	)
	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&nodeID, &sid, &cat, &content, &vecBlob, &provStr, &taintScore, &metaJSON, &createdNano, &updatedNano, &prevHash, &hash, &expiresAtNano,
	)
	if err != nil {
		return nil, err
	}

	var metadata map[string]string
	if len(metaJSON) > 0 {
		_ = json.Unmarshal([]byte(metaJSON), &metadata)
	}

	var expiresAt *time.Time
	if expiresAtNano.Valid {
		exp := time.Unix(0, expiresAtNano.Int64)
		expiresAt = &exp
	}

	return &brain.MemoryNode{
		ID:         nodeID,
		SessionID:  sid,
		Category:   cat,
		Content:    content,
		Vector:     decodeVector(vecBlob),
		Provenance: brain.ProvenanceTier(provStr),
		TaintScore: taintScore,
		Metadata:   metadata,
		PrevHash:   prevHash,
		Hash:       hash,
		CreatedAt:  time.Unix(0, createdNano),
		UpdatedAt:  time.Unix(0, updatedNano),
		ExpiresAt:  expiresAt,
	}, nil
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
