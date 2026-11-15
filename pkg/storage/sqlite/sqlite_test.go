package sqlite

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/embedding"
)

func TestFTS5Support(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "fts_test.db")
	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to init store: %v", err)
	}
	defer store.Close()

	_, err = store.db.Exec("CREATE VIRTUAL TABLE IF NOT EXISTS test_fts USING fts5(id UNINDEXED, content);")
	if err != nil {
		t.Fatalf("FTS5 is NOT supported in this SQLite driver: %v", err)
	}
	t.Log("✓ FTS5 is natively supported!")
}

func TestSQLiteStore_SemanticAndEpisodic(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_coppermind.db")

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create sqlite store: %v", err)
	}
	defer store.Close()

	embedder := embedding.NewLocalHashEmbedder(128)

	// Ingest sample memories
	memories := []struct {
		id       string
		category string
		content  string
	}{
		{id: "m1", category: "architecture", content: "Always use Go 1.27 pure-Go SQLite with WAL mode"},
		{id: "m2", category: "architecture", content: "Use Touch ID biometric authorization via Locksmith"},
		{id: "m3", category: "convention", content: "All commits must be cryptographically signed with GPG"},
	}

	for _, m := range memories {
		vec, err := embedder.Embed(ctx, m.content)
		if err != nil {
			t.Fatalf("embed error: %v", err)
		}
		err = store.Store(ctx, &brain.MemoryNode{
			ID:         m.id,
			SessionID:  "sess-alpha",
			Category:   m.category,
			Content:    m.content,
			Vector:     vec,
			Provenance: brain.ProvenanceLocalWorkspace,
			CreatedAt:  time.Now(),
		})
		if err != nil {
			t.Fatalf("store error: %v", err)
		}
	}

	// Semantic recall test: query about SQLite
	query := "Which database and journal mode do we use in Go?"
	queryVec, err := embedder.Embed(ctx, query)
	if err != nil {
		t.Fatalf("embed query error: %v", err)
	}

	results, err := store.RecallSemantic(ctx, queryVec, brain.MemoryFilter{
		Limit: 2,
	})
	if err != nil {
		t.Fatalf("recall error: %v", err)
	}

	if len(results) == 0 {
		t.Fatalf("expected results, got 0")
	}

	if results[0].Node.ID != "m1" {
		t.Errorf("expected top result to be m1 (SQLite), got %s (content: %q, score: %f)",
			results[0].Node.ID, results[0].Node.Content, results[0].Score)
	}

	// Episodic recall test
	nodes, err := store.RecallEpisodic(ctx, "sess-alpha", 10)
	if err != nil {
		t.Fatalf("episodic recall error: %v", err)
	}
	if len(nodes) != 3 {
		t.Errorf("expected 3 episodic nodes, got %d", len(nodes))
	}
}

func TestSQLiteStore_ConcurrentWriters(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "concurrent_test.db")

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create sqlite store: %v", err)
	}
	defer store.Close()

	var wg sync.WaitGroup
	subagents := 8
	writesPerAgent := 25

	for a := 0; a < subagents; a++ {
		wg.Add(1)
		go func(agentID int) {
			defer wg.Done()
			for i := 0; i < writesPerAgent; i++ {
				nodeID := fmt.Sprintf("agent-%d-item-%d", agentID, i)
				node := &brain.MemoryNode{
					ID:         nodeID,
					SessionID:  fmt.Sprintf("subagent-%d", agentID),
					Category:   "concurrency_test",
					Content:    fmt.Sprintf("Concurrent memory block %d from subagent %d", i, agentID),
					Vector:     []float32{float32(agentID), float32(i)},
					Provenance: brain.ProvenanceLocalWorkspace,
				}
				if err := store.Store(ctx, node); err != nil {
					t.Errorf("agent %d failed write %d: %v", agentID, i, err)
					return
				}
			}
		}(a)
	}

	wg.Wait()

	total, err := store.Count(ctx, "subagent-")
	if err != nil {
		t.Fatalf("count error: %v", err)
	}

	expectedTotal := subagents * writesPerAgent
	if total != expectedTotal {
		t.Errorf("expected %d total records across parallel subagents, got %d", expectedTotal, total)
	}
}

func TestADV_MerkleTamperDetection(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "tamper_test.db")

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create sqlite store: %v", err)
	}
	defer store.Close()

	session := "session-secure-merkle"
	for i := 1; i <= 4; i++ {
		err := store.Store(ctx, &brain.MemoryNode{
			ID:         fmt.Sprintf("node-%d", i),
			SessionID:  session,
			Category:   "audit",
			Content:    fmt.Sprintf("Legitimate audit log entry %d", i),
			Provenance: brain.ProvenanceLocalWorkspace,
			CreatedAt:  time.Unix(int64(1700000000+i*10), 0),
		})
		if err != nil {
			t.Fatalf("store node-%d failed: %v", i, err)
		}
	}

	// 1. Verify clean chain
	intact, count, badID, err := store.VerifySessionChain(ctx, session)
	if err != nil || !intact || count != 4 {
		t.Fatalf("expected chain intact with 4 verified nodes, got intact=%v, count=%d, badID=%s, err=%v", intact, count, badID, err)
	}

	// 2. Adversarial Tamper: Directly alter content of node-2 in SQLite
	_, err = store.db.Exec("UPDATE memory_nodes SET content = 'TAMPERED: Injected adversary log entry' WHERE id = 'node-2'")
	if err != nil {
		t.Fatalf("direct SQL update failed: %v", err)
	}

	// 3. Verify detection of content tampering
	intact, count, badID, err = store.VerifySessionChain(ctx, session)
	if intact {
		t.Fatalf("expected chain verification to FAIL after content tampering, but returned intact=true")
	}
	if badID != "node-2" {
		t.Errorf("expected badID to be node-2, got %q", badID)
	}
	if err == nil {
		t.Fatalf("expected tamper error, got nil")
	}
	t.Logf("✓ Successfully detected content tampering: %v", err)

	// 4. Adversarial Tamper: Alter prev_hash link
	_, err = store.db.Exec("UPDATE memory_nodes SET prev_hash = 'deadbeef00000000000000000000000000000000000000000000000000000000' WHERE id = 'node-3'")
	if err != nil {
		t.Fatalf("direct SQL update failed: %v", err)
	}

	intact, _, badID, err = store.VerifySessionChain(ctx, session)
	if intact {
		t.Fatalf("expected chain verification to FAIL after prev_hash tampering, but returned intact=true")
	}
	t.Logf("✓ Successfully detected link break at %s: %v", badID, err)
}

func TestSQLiteStore_RecallHybrid(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "hybrid_test.db")

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create sqlite store: %v", err)
	}
	defer store.Close()

	embedder := embedding.NewLocalHashEmbedder(128)

	memories := []struct {
		id       string
		category string
		content  string
	}{
		{id: "m_exact", category: "convention", content: "Always configure PRAGMA wal_autocheckpoint=1000 in Go SQLite"},
		{id: "m_fuzzy", category: "convention", content: "Configuring database journal settings for concurrent agent readers"},
		{id: "m_other", category: "unrelated", content: "Baking sourdough bread using stone ground flour and active starter"},
	}

	for _, m := range memories {
		vec, _ := embedder.Embed(ctx, m.content)
		_ = store.Store(ctx, &brain.MemoryNode{
			ID:         m.id,
			SessionID:  "session-hybrid",
			Category:   m.category,
			Content:    m.content,
			Vector:     vec,
			Provenance: brain.ProvenanceLocalWorkspace,
			CreatedAt:  time.Now(),
		})
	}

	query := "wal_autocheckpoint"
	qVec, _ := embedder.Embed(ctx, query)

	results, err := store.RecallHybrid(ctx, query, qVec, brain.MemoryFilter{
		Limit: 5,
	})
	if err != nil {
		t.Fatalf("RecallHybrid failed: %v", err)
	}

	if len(results) == 0 {
		t.Fatalf("expected hybrid results, got 0")
	}

	if results[0].Node.ID != "m_exact" {
		t.Errorf("expected m_exact to be ranked top due to exact BM25 keyword match, got %s", results[0].Node.ID)
	}
	t.Logf("✓ Top hybrid match: %s with composite score %f", results[0].Node.ID, results[0].Score)
}

func TestSQLiteStore_TTLAndVacuum(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "ttl_test.db")

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create sqlite store: %v", err)
	}
	defer store.Close()

	now := time.Now()
	expiredTime := now.Add(-1 * time.Hour)
	futureTime := now.Add(1 * time.Hour)

	// Ingest 1 expired memory, 1 active memory
	_ = store.Store(ctx, &brain.MemoryNode{
		ID:         "mem_expired",
		SessionID:  "sess-ttl",
		Category:   "temp",
		Content:    "Ephemeral memory that has already expired",
		ExpiresAt:  &expiredTime,
		CreatedAt:  now.Add(-2 * time.Hour),
		Provenance: brain.ProvenanceLocalWorkspace,
	})

	_ = store.Store(ctx, &brain.MemoryNode{
		ID:         "mem_active",
		SessionID:  "sess-ttl",
		Category:   "temp",
		Content:    "Active memory that will live for another hour",
		ExpiresAt:  &futureTime,
		CreatedAt:  now,
		Provenance: brain.ProvenanceLocalWorkspace,
	})

	// Purge expired
	purged, err := store.PurgeExpired(ctx)
	if err != nil {
		t.Fatalf("PurgeExpired failed: %v", err)
	}
	if purged != 1 {
		t.Errorf("expected 1 purged memory, got %d", purged)
	}

	// Verify only active remains
	count, err := store.Count(ctx, "sess-ttl")
	if err != nil || count != 1 {
		t.Errorf("expected 1 remaining memory, got %d (err: %v)", count, err)
	}

	// Vacuum
	if err := store.Vacuum(ctx); err != nil {
		t.Fatalf("Vacuum failed: %v", err)
	}
	t.Log("✓ Vacuum completed successfully")
}

func TestSQLiteStore_EpistemicAuthorityAndSupersession(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "authority_test.db")

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create sqlite store: %v", err)
	}
	defer store.Close()

	embedder := embedding.NewLocalHashEmbedder(128)
	now := time.Now()

	// 1. Ingest original rule (Tier 1 Architecture)
	origContent := "All distributed RPCs must use gRPC with mTLS and SPIFFE identity"
	origVec, _ := embedder.Embed(ctx, origContent)
	origNode := &brain.MemoryNode{
		ID:              "rule-rpc-v1",
		SessionID:       "arch-guidelines",
		Category:        "architecture",
		Content:         origContent,
		Vector:          origVec,
		Provenance:      brain.ProvenanceLocalWorkspace,
		AuthorityTier:   "TIER_1_ARCHITECTURE",
		LifecycleStatus: "ACTIVE",
		AuthorIdentity:  "lead-architect@corp.local",
		AuthorRole:      "architect",
		CreatedAt:       now.Add(-24 * time.Hour),
		UpdatedAt:       now.Add(-24 * time.Hour),
	}
	if err := store.Store(ctx, origNode); err != nil {
		t.Fatalf("failed to store original node: %v", err)
	}

	// 2. Ingest a proposed memory (e.g. from an unauthorized role)
	propContent := "We should switch all RPCs to HTTP/JSON without mTLS for simplicity"
	propVec, _ := embedder.Embed(ctx, propContent)
	propNode := &brain.MemoryNode{
		ID:              "prop-rpc-unsafe",
		SessionID:       "arch-guidelines",
		Category:        "architecture",
		Content:         propContent,
		Vector:          propVec,
		Provenance:      brain.ProvenanceLocalWorkspace,
		AuthorityTier:   "TIER_2_PRODUCT",
		LifecycleStatus: "PROPOSED",
		AuthorIdentity:  "po@corp.local",
		AuthorRole:      "product_owner",
		CreatedAt:       now.Add(-12 * time.Hour),
		UpdatedAt:       now.Add(-12 * time.Hour),
	}
	if err := store.Store(ctx, propNode); err != nil {
		t.Fatalf("failed to store proposed node: %v", err)
	}

	// 3. Verify that normal RecallSemantic ignores PROPOSED
	queryVec, _ := embedder.Embed(ctx, "What RPC protocol and identity standard do we use?")
	results, err := store.RecallSemantic(ctx, queryVec, brain.MemoryFilter{})
	if err != nil {
		t.Fatalf("RecallSemantic failed: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 active result, got %d", len(results))
	}
	if results[0].Node.ID != "rule-rpc-v1" {
		t.Errorf("expected rule-rpc-v1, got %s", results[0].Node.ID)
	}

	// 4. Supersede rule-rpc-v1 with rule-rpc-v2 (Tier 1 Architect)
	v2Content := "All distributed RPCs must use gRPC with mTLS, SPIFFE identity, and Conjoiner Ed25519 DPoP tokens"
	v2Vec, _ := embedder.Embed(ctx, v2Content)
	v2Node := &brain.MemoryNode{
		ID:         "rule-rpc-v2",
		SessionID:  "arch-guidelines",
		Category:   "architecture",
		Content:    v2Content,
		Vector:     v2Vec,
		Provenance: brain.ProvenanceLocalWorkspace,
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	rationale := "Upgrade security baseline to enforce Conjoiner Ed25519 DPoP cryptographic proof-of-possession tokens"
	advisory := "ADVISORY-2026-004"
	err = store.Supersede(ctx, v2Node, "rule-rpc-v1", rationale, advisory, "lead-architect@corp.local", "architect")
	if err != nil {
		t.Fatalf("Supersede failed: %v", err)
	}

	// 5. Verify rule-rpc-v1 is now SUPERSEDED and rule-rpc-v2 is ACTIVE
	v1After, err := store.GetByID(ctx, "rule-rpc-v1")
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}
	if v1After.LifecycleStatus != "SUPERSEDED" {
		t.Errorf("expected v1 to be SUPERSEDED, got %s", v1After.LifecycleStatus)
	}
	if v1After.SupersededByID != "rule-rpc-v2" {
		t.Errorf("expected v1 SupersededByID to be rule-rpc-v2, got %s", v1After.SupersededByID)
	}

	v2After, err := store.GetByID(ctx, "rule-rpc-v2")
	if err != nil {
		t.Fatalf("GetByID v2 failed: %v", err)
	}
	if v2After.LifecycleStatus != "ACTIVE" {
		t.Errorf("expected v2 to be ACTIVE, got %s", v2After.LifecycleStatus)
	}
	if v2After.SupersedesID != "rule-rpc-v1" {
		t.Errorf("expected v2 SupersedesID to be rule-rpc-v1, got %s", v2After.SupersedesID)
	}
	if v2After.AuthorityTier != "TIER_1_ARCHITECTURE" {
		t.Errorf("expected v2 AuthorityTier to inherit TIER_1_ARCHITECTURE, got %s", v2After.AuthorityTier)
	}

	// 6. Verify default RecallSemantic only returns ACTIVE v2
	activeResults, err := store.RecallSemantic(ctx, queryVec, brain.MemoryFilter{})
	if err != nil {
		t.Fatalf("RecallSemantic failed: %v", err)
	}
	if len(activeResults) != 1 {
		t.Fatalf("expected exactly 1 active result, got %d", len(activeResults))
	}
	if activeResults[0].Node.ID != "rule-rpc-v2" {
		t.Errorf("expected active result to be rule-rpc-v2, got %s", activeResults[0].Node.ID)
	}

	// 7. Verify IncludeSuperseded returns both v1 and v2
	allResults, err := store.RecallSemantic(ctx, queryVec, brain.MemoryFilter{IncludeSuperseded: true})
	if err != nil {
		t.Fatalf("RecallSemantic with IncludeSuperseded failed: %v", err)
	}
	if len(allResults) < 2 {
		t.Errorf("expected at least 2 results with IncludeSuperseded, got %d", len(allResults))
	}

	// 8. Verify DAG traversal via GetAncestors
	ancestors, err := store.GetAncestors(ctx, "rule-rpc-v2")
	if err != nil {
		t.Fatalf("GetAncestors failed: %v", err)
	}
	if len(ancestors) != 2 {
		t.Fatalf("expected 2 ancestors in lineage (v2 -> v1), got %d", len(ancestors))
	}
	if ancestors[0].ID != "rule-rpc-v2" || ancestors[1].ID != "rule-rpc-v1" {
		t.Errorf("unexpected ancestor chain: %s -> %s", ancestors[0].ID, ancestors[1].ID)
	}

	// 9. Verify audit trail retrieval
	auditRecords, err := store.GetAuditTrail(ctx, "rule-rpc-v2")
	if err != nil {
		t.Fatalf("GetAuditTrail failed: %v", err)
	}
	if len(auditRecords) != 1 {
		t.Fatalf("expected 1 audit record, got %d", len(auditRecords))
	}
	if auditRecords[0].Rationale != rationale || auditRecords[0].AdvisoryRef != advisory {
		t.Errorf("unexpected audit record values: %+v", auditRecords[0])
	}
}
