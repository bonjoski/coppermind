package postgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/bonjoski/coppermind/pkg/authz"
	"github.com/bonjoski/coppermind/pkg/brain"
)

func TestVectorFormattingAndParsing(t *testing.T) {
	vec := []float32{0.123456, -0.654321, 0.999999, 0.0}
	str := FormatVector(vec)
	if str != "[0.123456,-0.654321,0.999999,0.000000]" {
		t.Errorf("unexpected formatted vector: %s", str)
	}

	parsed, err := ParseVector(str)
	if err != nil {
		t.Fatalf("ParseVector failed: %v", err)
	}
	if len(parsed) != len(vec) {
		t.Fatalf("length mismatch: got %d, expected %d", len(parsed), len(vec))
	}
	for i := range vec {
		diff := parsed[i] - vec[i]
		if diff < -0.0001 || diff > 0.0001 {
			t.Errorf("mismatch at index %d: expected %f, got %f", i, vec[i], parsed[i])
		}
	}
}

func TestMerkleChainHashComputation(t *testing.T) {
	prev := ""
	h1 := ComputeNodeHash(prev, "node-1", "sess-1", "arch", "content 1", 1000)
	if len(h1) != 64 {
		t.Errorf("expected 64-char SHA256 hex string, got len %d", len(h1))
	}

	h2 := ComputeNodeHash(h1, "node-2", "sess-1", "arch", "content 2", 2000)
	if h2 == h1 {
		t.Errorf("chained hashes should differ")
	}
}

func TestPostgresStore_LiveIntegration(t *testing.T) {
	pgURL := os.Getenv("COPPERMIND_POSTGRES_URL")
	if pgURL == "" {
		t.Skip("Skipping live PostgreSQL integration test (COPPERMIND_POSTGRES_URL unset)")
	}

	ctx := context.Background()
	store, err := NewPostgresStore(ctx, Config{
		URL:       pgURL,
		Dimension: 128,
	})
	if err != nil {
		t.Fatalf("failed to connect to live postgres: %v", err)
	}
	defer store.Close()

	sessionID := "test-pg-sess"
	node := &brain.MemoryNode{
		ID:         "pg-node-1",
		SessionID:  sessionID,
		Category:   "architecture",
		Content:    "PostgreSQL 17 with pgvector cluster storage engine",
		Vector:     make([]float32, 128),
		Provenance: brain.ProvenanceLocalWorkspace,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	if err := store.Store(ctx, node); err != nil {
		t.Fatalf("failed to store node in postgres: %v", err)
	}

	count, err := store.Count(ctx, sessionID)
	if err != nil || count == 0 {
		t.Fatalf("failed to count nodes in postgres: %v (count: %d)", err, count)
	}

	_ = store.Delete(ctx, node.ID)
}

func TestPostgresStore_EpistemicAuthorityAndSupersession(t *testing.T) {
	pgURL := os.Getenv("COPPERMIND_POSTGRES_URL")
	if pgURL == "" {
		t.Skip("Skipping live PostgreSQL integration test (COPPERMIND_POSTGRES_URL unset)")
	}

	ctx := context.Background()
	store, err := NewPostgresStore(ctx, Config{
		URL:       pgURL,
		Dimension: 128,
	})
	if err != nil {
		t.Fatalf("failed to connect to live postgres: %v", err)
	}
	defer store.Close()

	enforcer := authz.NewDefaultPolicyEnforcer()
	sessionID := "test-epistemic-session"

	// 1. Architect writes initial Architecture guideline (Tier 1)
	archClaims := authz.SubjectClaims{
		Subject: "alice@corp.org",
		Role:    "architect",
		Scopes:  []string{"memory:architecture:write", "memory:read"},
	}

	writeReq1 := authz.MemoryWriteRequest{
		Category: "architecture",
		Content:  "All agent network communication must use mutual TLS with short-lived SPIFFE SVIDs.",
	}

	tier1, status1, err := enforcer.AuthorizeWrite(ctx, archClaims, writeReq1)
	if err != nil {
		t.Fatalf("architect authorization failed: %v", err)
	}

	dummyVec := make([]float32, 128)
	dummyVec[0] = 0.8
	dummyVec[1] = 0.5

	node1 := &brain.MemoryNode{
		ID:              "node-guideline-v1",
		SessionID:       sessionID,
		Category:        writeReq1.Category,
		Content:         writeReq1.Content,
		Vector:          dummyVec,
		Provenance:      brain.ProvenanceLocalWorkspace,
		AuthorityTier:   authz.TierToString(tier1),
		LifecycleStatus: string(status1),
		AuthorIdentity:  archClaims.Subject,
		AuthorRole:      archClaims.Role,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	if err := store.Store(ctx, node1); err != nil {
		t.Fatalf("failed to store node1 in postgres: %v", err)
	}
	defer store.Delete(ctx, node1.ID)

	// 2. Active recall should find node1
	results, err := store.RecallSemantic(ctx, dummyVec, brain.MemoryFilter{
		SessionID: sessionID,
		Limit:     5,
	})
	if err != nil {
		t.Fatalf("RecallSemantic failed: %v", err)
	}
	if len(results) == 0 || results[0].Node.ID != node1.ID {
		t.Fatalf("expected node1 to be returned in active recall, got %v", results)
	}

	// 3. Product owner tries to supersede node1 with a conflicting architectural rule
	poClaims := authz.SubjectClaims{
		Subject: "bob@corp.org",
		Role:    "product_owner",
		Scopes:  []string{"memory:product:write"},
	}

	err = enforcer.ValidateSupersession(ctx, poClaims, tier1, node1.ID, "node-po-attempt", nil)
	if !errors.Is(err, authz.ErrForbiddenAuthority) {
		t.Fatalf("expected ErrForbiddenAuthority when PO tries to supersede architecture, got %v", err)
	}

	// 4. Architect legitimately supersedes node1 with node2
	archUpdateClaims := authz.SubjectClaims{
		Subject: "carol@corp.org",
		Role:    "architect",
		Scopes:  []string{"memory:architecture:write"},
	}

	err = enforcer.ValidateSupersession(ctx, archUpdateClaims, tier1, node1.ID, "node-guideline-v2", func(id string) ([]string, error) {
		return store.GetAncestors(ctx, id)
	})
	if err != nil {
		t.Fatalf("expected architect supersession validation to pass, got %v", err)
	}

	node2 := &brain.MemoryNode{
		ID:         "node-guideline-v2",
		SessionID:  sessionID,
		Category:   "architecture",
		Content:    "All agent network communication must use mutual TLS with short-lived SPIFFE SVIDs and Ed25519 DPoP proofs.",
		Vector:     dummyVec,
		Provenance: brain.ProvenanceLocalWorkspace,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	err = store.Supersede(ctx, node2, node1.ID, "ADR-045: Standardized on Conjoiner Ed25519 DPoP tokens alongside mTLS", "ADR-045", archUpdateClaims.Subject, archUpdateClaims.Role)
	if err != nil {
		t.Fatalf("store.Supersede failed: %v", err)
	}
	defer store.Delete(ctx, node2.ID)

	// 5. Verify node1 is now marked SUPERSEDED
	updatedNode1, err := store.GetByID(ctx, node1.ID)
	if err != nil {
		t.Fatalf("failed to get node1: %v", err)
	}
	if updatedNode1.LifecycleStatus != string(authz.StatusSuperseded) {
		t.Fatalf("expected node1 lifecycle_status to be SUPERSEDED, got %q", updatedNode1.LifecycleStatus)
	}
	if updatedNode1.SupersededByID != node2.ID {
		t.Fatalf("expected node1 superseded_by_id to be %q, got %q", node2.ID, updatedNode1.SupersededByID)
	}

	// 6. Verify audit history in memory_supersessions
	history, err := store.GetSupersessionHistory(ctx, node1.ID)
	if err != nil {
		t.Fatalf("failed to get supersession history: %v", err)
	}
	if len(history) == 0 {
		t.Fatalf("expected at least 1 supersession record, got 0")
	}
	if history[0].SupersedingID != node2.ID || history[0].SupersededID != node1.ID {
		t.Fatalf("unexpected supersession record: %+v", history[0])
	}

	// 7. Verify Active Recall returns ONLY node2 (active) and excludes node1 (superseded)
	activeResults, err := store.RecallSemantic(ctx, dummyVec, brain.MemoryFilter{
		SessionID:         sessionID,
		IncludeSuperseded: false,
		Limit:             5,
	})
	if err != nil {
		t.Fatalf("RecallSemantic failed: %v", err)
	}
	for _, res := range activeResults {
		if res.Node.ID == node1.ID {
			t.Fatalf("superseded node1 was returned in active recall query!")
		}
	}
	foundNode2 := false
	for _, res := range activeResults {
		if res.Node.ID == node2.ID {
			foundNode2 = true
			break
		}
	}
	if !foundNode2 {
		t.Fatalf("active node2 was not returned in active recall query!")
	}

	// 8. Query with IncludeSuperseded: true returns both nodes
	allResults, err := store.RecallSemantic(ctx, dummyVec, brain.MemoryFilter{
		SessionID:         sessionID,
		IncludeSuperseded: true,
		Limit:             5,
	})
	if err != nil {
		t.Fatalf("RecallSemantic with IncludeSuperseded failed: %v", err)
	}
	if len(allResults) < 2 {
		t.Fatalf("expected at least 2 nodes with IncludeSuperseded: true, got %d", len(allResults))
	}

	// 9. Cycle prevention test: node1 attempting to supersede node2 should fail cycle check
	errCycle := enforcer.ValidateSupersession(ctx, archClaims, tier1, node2.ID, node1.ID, func(id string) ([]string, error) {
		return store.GetAncestors(ctx, id)
	})
	if !errors.Is(errCycle, authz.ErrCyclicSupersession) {
		t.Fatalf("expected ErrCyclicSupersession when creating cycle node2 -> node1, got %v", errCycle)
	}
}
