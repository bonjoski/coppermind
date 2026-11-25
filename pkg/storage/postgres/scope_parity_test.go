package postgres

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/scope"
	"github.com/bonjoski/coppermind/pkg/storage"
)

func TestPostgresScopePredicateBuilderAndMerkleV2(t *testing.T) {
	// 1. ModeAncestors generates ANY($N) with exact ancestors (zero LIKE wildcards!)
	q, args, nextIdx := appendPostgresScopePredicate("SELECT 1 FROM memory_nodes WHERE 1=1", nil, 1, "platform/payments_v2/webhooks", scope.ModeAncestors)
	if !strings.Contains(q, "scope = ANY($1)") || strings.Contains(q, "LIKE") || len(args) != 1 || nextIdx != 2 {
		t.Fatalf("unexpected ancestors predicate: q=%q args=%d nextIdx=%d", q, len(args), nextIdx)
	}

	// 2. ModeSubtree uses exact + starts_with (immune to '_' / '%' LIKE wildcard injection)
	q, args, nextIdx = appendPostgresScopePredicate("SELECT 1 FROM memory_nodes WHERE 1=1", nil, 3, "platform/payments_v2", scope.ModeSubtree)
	if !strings.Contains(q, "scope = $3 OR starts_with(scope, $4)") || len(args) != 2 || args[0] != "platform/payments_v2" || args[1] != "platform/payments_v2/" || nextIdx != 5 {
		t.Fatalf("unexpected subtree predicate: q=%q args=%v nextIdx=%d", q, args, nextIdx)
	}

	// 3. ModeLineage combines ANY($N) + starts_with($N+1)
	q, args, nextIdx = appendPostgresScopePredicate("SELECT 1 FROM memory_nodes WHERE 1=1", nil, 1, "platform/payments", scope.ModeLineage)
	if !strings.Contains(q, "scope = ANY($1) OR starts_with(scope, $2)") || len(args) != 2 || nextIdx != 3 {
		t.Fatalf("unexpected lineage predicate: q=%q args=%v nextIdx=%d", q, args, nextIdx)
	}

	// 4. ModeAll adds zero scope restrictions
	q, args, nextIdx = appendPostgresScopePredicate("SELECT 1", nil, 1, "platform/payments", scope.ModeAll)
	if q != "SELECT 1" || len(args) != 0 || nextIdx != 1 {
		t.Fatalf("ModeAll should not add SQL predicate: q=%q", q)
	}

	// 5. Merkle v1/v2 parity: empty scope preserves v1 hash; non-empty binds scope into v2 hash
	hV1 := ComputeNodeHash("prev", "id1", "sess", "architecture", "content", 12345)
	hGlobal := ComputeNodeHashScoped("prev", "id1", "sess", "", "architecture", "content", 12345)
	if hV1 != hGlobal {
		t.Fatalf("legacy global hash mismatch: v1=%s vs scoped('')=%s", hV1, hGlobal)
	}
	hScoped := ComputeNodeHashScoped("prev", "id1", "sess", "platform/payments", "architecture", "content", 12345)
	hEscalated := ComputeNodeHashScoped("prev", "id1", "sess", "platform", "architecture", "content", 12345)
	if hScoped == hV1 || hScoped == hEscalated {
		t.Fatalf("Merkle v2 failed to differentiate scoped vs global/parent hashes")
	}

	// 6. pgNodeMatchesFilter enforces sibling isolation for ExpandGraphNeighbors
	now := time.Now().UnixNano()
	siblingNode := &brain.MemoryNode{
		ID:              "n-auth",
		Scope:           "platform/auth",
		LifecycleStatus: "ACTIVE",
	}
	ancestorNode := &brain.MemoryNode{
		ID:              "n-plat",
		Scope:           "platform",
		LifecycleStatus: "ACTIVE",
	}
	flt := brain.MemoryFilter{Scope: "platform/payments", ScopeMode: scope.ModeAncestors}
	if pgNodeMatchesFilter(siblingNode, flt, now) {
		t.Fatal("SECURITY VIOLATION: pgNodeMatchesFilter admitted sibling scope")
	}
	if !pgNodeMatchesFilter(ancestorNode, flt, now) {
		t.Fatal("pgNodeMatchesFilter rejected valid ancestor scope")
	}
}

func TestLivePostgresScopeParity(t *testing.T) {
	pgURL := strings.TrimSpace(os.Getenv("COPPERMIND_TEST_POSTGRES_URL"))
	if pgURL == "" {
		t.Skip("COPPERMIND_TEST_POSTGRES_URL not set; skipping live PostgreSQL 17 scope parity test")
	}
	ctx := context.Background()
	store, err := NewPostgresStore(ctx, Config{URL: pgURL, Dimension: 128})
	if err != nil {
		t.Fatalf("NewPostgresStore failed: %v", err)
	}
	defer store.Close()

	sess := fmt.Sprintf("pg-scope-%d", time.Now().UnixNano())
	vec := make([]float32, 128)
	vec[0] = 1.0

	pNode := &brain.MemoryNode{
		ID: "pg_plat_" + sess, SessionID: sess, Scope: "platform", Category: "architecture",
		Content: "Platform wide PostgreSQL rule for logging.", Vector: vec, Provenance: brain.ProvenanceLocalWorkspace,
	}
	cNode := &brain.MemoryNode{
		ID: "pg_pay_" + sess, SessionID: sess, Scope: "platform/payments_v2", Category: "architecture",
		Content: "Payments PostgreSQL rule for idempotency.", Vector: vec, Provenance: brain.ProvenanceLocalWorkspace,
	}
	sNode := &brain.MemoryNode{
		ID: "pg_auth_" + sess, SessionID: sess, Scope: "platform/auth", Category: "architecture",
		Content: "Auth sibling PostgreSQL rule for OIDC.", Vector: vec, Provenance: brain.ProvenanceLocalWorkspace,
	}
	for _, n := range []*brain.MemoryNode{pNode, cNode, sNode} {
		if err := store.Store(ctx, n); err != nil {
			t.Fatalf("Store(%s) failed: %v", n.ID, err)
		}
		defer store.Delete(ctx, n.ID)
	}

	res, err := store.RecallSemantic(ctx, vec, brain.MemoryFilter{
		SessionID: sess, Scope: "platform/payments_v2", ScopeMode: scope.ModeAncestors, Limit: 10,
	})
	if err != nil {
		t.Fatalf("RecallSemantic failed: %v", err)
	}
	if len(res) != 2 {
		t.Fatalf("expected 2 ancestor nodes from Postgres, got %d", len(res))
	}

	if err := store.Supersede(ctx, &brain.MemoryNode{
		ID: "pg_bad_" + sess, SessionID: sess, Scope: "platform/payments_v2", Category: "architecture",
		Content: "Cross-scope override", Vector: vec, Provenance: brain.ProvenanceLocalWorkspace, AuthorityTier: "TIER_1_ARCHITECTURE",
	}, pNode.ID, "override", "", "tester", "architect"); !errors.Is(err, scope.ErrCrossScopeSupersession) {
		t.Fatalf("expected ErrCrossScopeSupersession in Postgres, got %v", err)
	}

	if _, err := store.ListScopes(ctx); err != nil {
		t.Fatalf("Postgres ListScopes failed: %v", err)
	}
	cart, err := store.QueryActiveNodesForCartridge(ctx, storage.CartridgeFilter{Scope: "platform/payments_v2", ScopeMode: scope.ModeSubtree})
	if err != nil || len(cart) < 1 {
		t.Fatalf("Postgres QueryActiveNodesForCartridge failed: len=%d err=%v", len(cart), err)
	}
	if ok, _, _, err := store.VerifySessionChain(ctx, sess); !ok || err != nil {
		t.Fatalf("Postgres Merkle v2 verification failed: ok=%t err=%v", ok, err)
	}
}
