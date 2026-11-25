package brain_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/embedding"
	"github.com/bonjoski/coppermind/pkg/scope"
	"github.com/bonjoski/coppermind/pkg/scratchpad"
	"github.com/bonjoski/coppermind/pkg/storage/sqlite"
)

func TestScopeSpecificityRerankingAndTierPreservation(t *testing.T) {
	now := time.Now()
	makeRes := func(id, sc, tier string, rawScore float32) *brain.SearchResult {
		return &brain.SearchResult{
			Node: &brain.MemoryNode{
				ID:            id,
				Scope:         sc,
				AuthorityTier: tier,
				Provenance:    brain.ProvenanceLocalWorkspace,
				Content:       "stripe webhook signature idempotency policy " + id,
				CreatedAt:     now,
				UpdatedAt:     now,
			},
			Score: rawScore,
		}
	}

	results := []*brain.SearchResult{
		makeRes("global-tier1", "", "TIER_1_ARCHITECTURE", 0.80),
		makeRes("platform-tier1", "platform", "TIER_1_ARCHITECTURE", 0.80),
		makeRes("payments-tier1", "platform/payments", "TIER_1_ARCHITECTURE", 0.80),
		makeRes("webhooks-tier1", "platform/payments/webhooks", "TIER_1_ARCHITECTURE", 0.80),
	}

	cfg := brain.DefaultRerankConfig()
	cfg.ActiveScope = "platform/payments/webhooks"
	cfg.DisableMMR = true
	cfg.Now = now

	ranked := brain.RerankResults(results, cfg)
	wantOrder := []string{"webhooks-tier1", "payments-tier1", "platform-tier1", "global-tier1"}
	for i, want := range wantOrder {
		if ranked[i].Node.ID != want {
			t.Fatalf("rank[%d] = %s (score=%.4f, scopeAff=%.2f), want %s",
				i, ranked[i].Node.ID, ranked[i].Score, ranked[i].Breakdown.ScopeAffinity, want)
		}
	}

	// TIER_0_SOVEREIGN platform invariant must outrank noisy TIER_3_EPISODIC local note at equal semantic score
	mixed := []*brain.SearchResult{
		makeRes("local-episodic", "platform/payments/webhooks", "TIER_3_EPISODIC", 0.80),
		makeRes("platform-sovereign", "platform", "TIER_0_SOVEREIGN", 0.80),
	}
	rankedMixed := brain.RerankResults(mixed, cfg)
	if rankedMixed[0].Node.ID != "platform-sovereign" {
		t.Fatalf("expected TIER_0_SOVEREIGN platform invariant to outrank TIER_3_EPISODIC leaf note, got %s (%.4f vs %.4f)",
			rankedMixed[0].Node.ID, rankedMixed[0].Score, rankedMixed[1].Score)
	}
}

func TestAdversarialManagerScopeValidationAndCrossScopeSupersession(t *testing.T) {
	dir := t.TempDir()
	store, err := sqlite.NewSQLiteStore(filepath.Join(dir, "brain_scope.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	mgr := brain.NewManager(store, embedding.NewLocalHashEmbedder(128), scratchpad.NewMemoryScratchpad())
	defer mgr.Close()
	ctx := context.Background()

	// 1. Invalid scopes fail closed on Remember and Recall
	if _, err := mgr.Remember(ctx, brain.RememberRequest{
		Category: "architecture",
		Scope:    "platform/../evil",
		Content:  "Attempted scope traversal",
	}); !errors.Is(err, scope.ErrInvalidScope) {
		t.Fatalf("expected ErrInvalidScope on Remember, got %v", err)
	}

	if _, err := mgr.Recall(ctx, brain.RecallRequest{
		Query: "traversal",
		Scope: "platform/%",
	}); !errors.Is(err, scope.ErrInvalidScope) {
		t.Fatalf("expected ErrInvalidScope on Recall, got %v", err)
	}

	if _, err := mgr.Recall(ctx, brain.RecallRequest{
		Query:     "bad mode",
		Scope:     "platform",
		ScopeMode: scope.Mode("bogus"),
	}); !errors.Is(err, scope.ErrInvalidScopeMode) {
		t.Fatalf("expected ErrInvalidScopeMode on Recall, got %v", err)
	}

	// 2. Cross-scope supersession MUST fail closed
	parent, err := mgr.Remember(ctx, brain.RememberRequest{
		Category: "architecture",
		Scope:    "platform",
		Content:  "Platform invariant: all HTTP services must emit structured JSON logs.",
	})
	if err != nil {
		t.Fatalf("store parent failed: %v", err)
	}

	if _, err := mgr.Remember(ctx, brain.RememberRequest{
		Category:     "architecture",
		Scope:        "platform/payments/webhooks",
		Content:      "Disable logging for webhooks.",
		SupersedesID: parent.ID,
		Rationale:    "Attempting unauthorized cross-scope tombstone",
	}); !errors.Is(err, scope.ErrCrossScopeSupersession) {
		t.Fatalf("SECURITY VIOLATION: expected ErrCrossScopeSupersession, got %v", err)
	}
}
