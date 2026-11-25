package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/embedding"
	"github.com/bonjoski/coppermind/pkg/graph"
	"github.com/bonjoski/coppermind/pkg/scope"
	"github.com/bonjoski/coppermind/pkg/scratchpad"
	"github.com/bonjoski/coppermind/pkg/storage"
)

func TestScopeInheritanceModesGraphIsolationAndMerkleTamper(t *testing.T) {
	dir := t.TempDir()
	store, err := NewSQLiteStore(filepath.Join(dir, "scopes.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()
	mgr := brain.NewManager(store, embedding.NewLocalHashEmbedder(128), scratchpad.NewMemoryScratchpad())
	defer mgr.Close()

	// Seed multi-level platform hierarchy + sibling branch + child branch + underscore segment
	seed := func(sess, sc, cat, content string) *brain.MemoryNode {
		t.Helper()
		n, err := mgr.Remember(ctx, brain.RememberRequest{
			SessionID:  sess,
			Scope:      sc,
			Category:   cat,
			Content:    content,
			Provenance: brain.ProvenanceLocalWorkspace,
		})
		if err != nil {
			t.Fatalf("Remember(scope=%q) failed: %v", sc, err)
		}
		return n
	}

	nGlobal := seed("sess-1", "", "architecture", "Global rule touching pkg/http/server.go: always enforce timeouts on HTTP servers.")
	nPlatform := seed("sess-1", "platform", "architecture", "Platform rule touching pkg/http/server.go: propagate X-Request-ID across all services.")
	nPayments := seed("sess-1", "platform/payments_v2", "architecture", "Payments rule touching pkg/http/server.go: require Idempotency-Key header for 24h.")
	nWebhooks := seed("sess-1", "platform/payments_v2/webhooks", "convention", "Webhook rule touching pkg/http/server.go: verify Stripe-Signature over raw bytes.")
	nWebhookV2 := seed("sess-1", "platform/payments_v2/webhooks/v2", "convention", "Webhook v2 rule: batch retry queue.")
	nAuthSibling := seed("sess-1", "platform/auth", "architecture", "Auth sibling rule touching pkg/http/server.go: rotate OIDC JWKS every 30 days.")

	// 1. Default ancestors recall from leaf scope: includes global + platform + payments_v2 + webhooks; excludes auth sibling & webhooks/v2 child
	res, err := mgr.Recall(ctx, brain.RecallRequest{
		Query:  "HTTP server rule X-Request-ID Idempotency-Key Stripe-Signature OIDC JWKS",
		Scope:  "platform/payments_v2/webhooks",
		Hybrid: true,
		Hops:   2, // Also tests Graph-RAG sibling isolation via shared entity file:pkg/http/server.go!
		Limit:  20,
	})
	if err != nil {
		t.Fatalf("scoped Recall failed: %v", err)
	}
	gotIDs := make(map[string]bool)
	for _, r := range res {
		gotIDs[r.Node.ID] = true
	}
	for _, want := range []*brain.MemoryNode{nGlobal, nPlatform, nPayments, nWebhooks} {
		if !gotIDs[want.ID] {
			t.Fatalf("ancestors recall missing expected node %s (scope=%q)", want.ID, want.Scope)
		}
	}
	if gotIDs[nAuthSibling.ID] {
		t.Fatalf("SECURITY VIOLATION: sibling scope %q leaked into %q recall (even via 2-hop shared file entity)", nAuthSibling.Scope, "platform/payments_v2/webhooks")
	}
	if gotIDs[nWebhookV2.ID] {
		t.Fatalf("descendant scope %q should not appear in ModeAncestors recall", nWebhookV2.Scope)
	}

	// 2. Exact mode: returns ONLY exact target scope
	exactRes, err := mgr.Recall(ctx, brain.RecallRequest{
		Query:     "HTTP server rule",
		Scope:     "platform/payments_v2",
		ScopeMode: scope.ModeExact,
		Hybrid:    true,
		Hops:      2,
		Limit:     10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(exactRes) != 1 || exactRes[0].Node.ID != nPayments.ID {
		t.Fatalf("expected only %s in ModeExact, got %d results", nPayments.ID, len(exactRes))
	}

	// 3. Subtree mode: returns target + descendants (payments_v2, webhooks, webhooks/v2), excludes platform & auth
	subRes, err := mgr.Recall(ctx, brain.RecallRequest{
		Query:     "rule queue retry Stripe Idempotency",
		Scope:     "platform/payments_v2",
		ScopeMode: scope.ModeSubtree,
		Hybrid:    true,
		Limit:     20,
	})
	if err != nil {
		t.Fatal(err)
	}
	subIDs := make(map[string]bool)
	for _, r := range subRes {
		subIDs[r.Node.ID] = true
	}
	if !subIDs[nPayments.ID] || !subIDs[nWebhooks.ID] || !subIDs[nWebhookV2.ID] {
		t.Fatalf("subtree recall missing expected descendants: %v", subIDs)
	}
	if subIDs[nPlatform.ID] || subIDs[nGlobal.ID] || subIDs[nAuthSibling.ID] {
		t.Fatalf("subtree recall leaked non-subtree node: %v", subIDs)
	}

	// 4. ListScopes & QueryActiveNodesForCartridge & ListTimeline parity
	scopes, err := store.ListScopes(ctx)
	if err != nil {
		t.Fatalf("ListScopes failed: %v", err)
	}
	if len(scopes) != 6 {
		t.Fatalf("expected 6 distinct scopes, got %d: %+v", len(scopes), scopes)
	}
	cartNodes, err := store.QueryActiveNodesForCartridge(ctx, storage.CartridgeFilter{
		Scope:     "platform/payments_v2",
		ScopeMode: scope.ModeSubtree,
	})
	if err != nil {
		t.Fatalf("QueryActiveNodesForCartridge failed: %v", err)
	}
	if len(cartNodes) != 3 {
		t.Fatalf("expected 3 subtree nodes in cartridge query, got %d", len(cartNodes))
	}
	tlNodes, err := store.ListTimeline(ctx, storage.TimelineFilter{
		Scope:     "platform/payments_v2/webhooks",
		ScopeMode: scope.ModeAncestors,
		Limit:     20,
	})
	if err != nil {
		t.Fatalf("ListTimeline failed: %v", err)
	}
	if len(tlNodes) != 4 {
		t.Fatalf("expected 4 ancestor timeline nodes, got %d", len(tlNodes))
	}

	// 5. Cross-scope supersession rejected atomically inside SQLite execSupersede too
	if err := store.Supersede(ctx, &brain.MemoryNode{
		ID:            "mem_evil_sup",
		SessionID:     "sess-1",
		Category:      "architecture",
		Scope:         "platform/payments_v2/webhooks",
		Content:       "Attempted direct store cross-scope supersede",
		Provenance:    brain.ProvenanceLocalWorkspace,
		AuthorityTier: "TIER_1_ARCHITECTURE",
	}, nPlatform.ID, "trying to override parent", "", "tester", "architect"); !errors.Is(err, scope.ErrCrossScopeSupersession) {
		t.Fatalf("SECURITY VIOLATION: direct SQLite Supersede allowed cross-scope override: %v", err)
	}

	// 6. Contradiction Radar emits ancestor refinement advisory rather than silent sibling bleed
	warnings := graph.DetectConflicts(ctx, mgr, nWebhooks)
	for _, w := range warnings {
		if w.ConflictingNodeID == nAuthSibling.ID {
			t.Fatalf("DetectConflicts leaked sibling scope node %s", nAuthSibling.ID)
		}
	}

	// 7. Merkle v2 integrity: valid before tampering, FAILS CLOSED if scope is wiped to '' or escalated to 'platform'
	ok, cnt, badID, err := store.VerifySessionChain(ctx, "sess-1")
	if err != nil || !ok || cnt != 6 {
		t.Fatalf("expected intact Merkle chain of 6 nodes, got ok=%t cnt=%d bad=%s err=%v", ok, cnt, badID, err)
	}

	// Tamper directly in SQLite: escalate nWebhooks scope -> "" (vault-global)
	if _, err := store.db.Exec("UPDATE memory_nodes SET scope = '' WHERE id = ?", nWebhooks.ID); err != nil {
		t.Fatal(err)
	}
	ok, _, badID, err = store.VerifySessionChain(ctx, "sess-1")
	if ok || err == nil || badID != nWebhooks.ID {
		t.Fatalf("SECURITY VIOLATION: Merkle v2 failed to detect SQLite scope escalation to global! ok=%t bad=%s err=%v", ok, badID, err)
	}
}

func TestScopedMultiAgentConcurrencyN8(t *testing.T) {
	dir := t.TempDir()
	store, err := NewSQLiteStore(filepath.Join(dir, "n8_scopes.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()
	mgr := brain.NewManager(store, embedding.NewLocalHashEmbedder(128), scratchpad.NewMemoryScratchpad())
	defer mgr.Close()

	// Seed shared platform invariant
	if _, err := mgr.Remember(ctx, brain.RememberRequest{
		SessionID:  "root",
		Scope:      "platform",
		Category:   "architecture",
		Content:    "Shared platform invariant: all services expose /healthz.",
		Provenance: brain.ProvenanceLocalWorkspace,
	}); err != nil {
		t.Fatal(err)
	}

	const workers = 8
	var wg sync.WaitGroup
	errCh := make(chan error, workers*4)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			sc := fmt.Sprintf("platform/svc_%d", id)
			sess := fmt.Sprintf("wt-%d", id)
			for j := 0; j < 5; j++ {
				if _, err := mgr.Remember(ctx, brain.RememberRequest{
					SessionID:  sess,
					Scope:      sc,
					Category:   "convention",
					Content:    fmt.Sprintf("Service %d convention #%d for /healthz checks", id, j),
					Provenance: brain.ProvenanceLocalWorkspace,
				}); err != nil {
					errCh <- err
					return
				}
				res, err := mgr.Recall(ctx, brain.RecallRequest{
					Query:  "/healthz convention",
					Scope:  sc,
					Hybrid: true,
					Limit:  10,
				})
				if err != nil {
					errCh <- err
					return
				}
				for _, r := range res {
					if r.Node.Scope != "" && r.Node.Scope != "platform" && r.Node.Scope != sc {
						errCh <- fmt.Errorf("worker %d leaked sibling scope %q", id, r.Node.Scope)
						return
					}
				}
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("N=8 concurrent scoped operation failed: %v", err)
	}
}

func TestLegacyPreV09DatabaseMigratesScopeColumnCleanly(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "legacy_v08.db")

	// Simulate a pre-v0.9.0 SQLite database whose memory_nodes table lacks the `scope` column.
	rawDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed opening raw legacy sqlite db: %v", err)
	}
	legacyDDL := `
	CREATE TABLE memory_nodes (
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
		hash TEXT NOT NULL DEFAULT ''
	);
	INSERT INTO memory_nodes (id, session_id, category, content, provenance, created_at, updated_at)
	VALUES ('legacy-1', 'legacy-sess', 'architecture', 'Legacy global rule before v0.9', 'TRUST_LOCAL_WORKSPACE', 1000, 1000);
	`
	if _, err := rawDB.Exec(legacyDDL); err != nil {
		rawDB.Close()
		t.Fatalf("failed seeding legacy v0.8 schema: %v", err)
	}
	rawDB.Close()

	// Opening with v0.9+ NewSQLiteStore MUST migrate cleanly without "no such column: scope".
	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStore failed to migrate pre-v0.9 database: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	mgr := brain.NewManager(store, embedding.NewLocalHashEmbedder(128), scratchpad.NewMemoryScratchpad())
	defer mgr.Close()

	// Verify scoped writes and ancestor recall work alongside migrated legacy global rows.
	if _, err := mgr.Remember(ctx, brain.RememberRequest{
		SessionID:  "v09-sess",
		Scope:      "bonjoski/airlock",
		Category:   "architecture",
		Content:    "Airlock child rule: Seatbelt deny rules come after allow rules.",
		Provenance: brain.ProvenanceLocalWorkspace,
	}); err != nil {
		t.Fatalf("scoped Remember after legacy migration failed: %v", err)
	}

	scopes, err := store.ListScopes(ctx)
	if err != nil {
		t.Fatalf("ListScopes after legacy migration failed: %v", err)
	}
	if len(scopes) != 2 {
		t.Fatalf("expected 2 scopes ('' and 'bonjoski/airlock'), got %d: %+v", len(scopes), scopes)
	}
}
