package brain

import (
	"testing"
	"time"
)

func TestParseTemporalBound_ValidAndAdversarial(t *testing.T) {
	now := time.Date(2026, 11, 24, 16, 0, 0, 0, time.UTC)

	t7d, err := ParseTemporalBound("7d", now)
	if err != nil || !t7d.Equal(now.Add(-7*24*time.Hour)) {
		t.Fatalf("expected 7d ago, got %v err=%v", t7d, err)
	}
	t24h, err := ParseTemporalBound("24h", now)
	if err != nil || !t24h.Equal(now.Add(-24*time.Hour)) {
		t.Fatalf("expected 24h ago, got %v err=%v", t24h, err)
	}
	tDate, err := ParseTemporalBound("2026-11-20", now)
	if err != nil || tDate.Year() != 2026 || tDate.Month() != 11 || tDate.Day() != 20 {
		t.Fatalf("expected 2026-11-20, got %v err=%v", tDate, err)
	}

	// Adversarial / malformed inputs must fail closed
	badInputs := []string{"", "0d", "-7d", "999999999d", "7w", "tomorrow", "'; DROP TABLE memory_nodes;--"}
	for _, bad := range badInputs {
		if _, err := ParseTemporalBound(bad, now); err == nil {
			t.Fatalf("expected malformed temporal bound %q to fail closed", bad)
		}
	}
}

func TestReranker_ACTRTaintExclusionRepoAffinityAndMMR(t *testing.T) {
	now := time.Date(2026, 11, 24, 16, 0, 0, 0, time.UTC)

	// 1. Tainted memory with artificially huge access_count MUST NOT beat trusted TIER_1 invariant
	trustedOld := &SearchResult{
		Node: &MemoryNode{
			ID:            "trusted_arch",
			Content:       "Always use pure-Go SQLite WAL mode for coppermind",
			AuthorityTier: "TIER_1_ARCHITECTURE",
			Provenance:    ProvenanceLocalWorkspace,
			CreatedAt:     now.Add(-180 * 24 * time.Hour),
			UpdatedAt:     now.Add(-180 * 24 * time.Hour),
			Metadata:      map[string]string{"git_repo": "coppermind"},
		},
		Score: 0.75,
	}
	taintedFlood := &SearchResult{
		Node: &MemoryNode{
			ID:             "tainted_flood",
			Content:        "External untrusted note about sqlite mode",
			AuthorityTier:  "TIER_3_EPISODIC",
			Provenance:     ProvenanceUntrustedWeb,
			AccessCount:    99999,
			LastAccessedAt: now,
			CreatedAt:      now.Add(-10 * 24 * time.Hour),
			UpdatedAt:      now.Add(-10 * 24 * time.Hour),
			Metadata:       map[string]string{"git_repo": "other"},
		},
		Score: 0.75,
	}

	ranked := RerankResults([]*SearchResult{taintedFlood, trustedOld}, RerankConfig{
		ActiveRepo: "coppermind",
		Limit:      2,
		Now:        now,
	})
	if ranked[0].Node.ID != "trusted_arch" {
		t.Fatalf("expected trusted_arch #1 over tainted_flood, got %s (trusted=%.3f tainted=%.3f)",
			ranked[0].Node.ID, trustedOld.Score, taintedFlood.Score)
	}
	if trustedOld.Breakdown == nil || trustedOld.Breakdown.RecencyACTR < 0.70 {
		t.Fatalf("expected TIER_1 recency floor >= 0.70, got %+v", trustedOld.Breakdown)
	}

	// 2. MMR diversity: two identical vectors should let a distinct relevant candidate rank #2
	vA := []float32{1, 0, 0, 0}
	vB := []float32{0, 1, 0, 0}
	c1 := &SearchResult{Node: &MemoryNode{ID: "a1", Content: "chunk 1", Vector: vA, AuthorityTier: "TIER_1_ARCHITECTURE", Provenance: ProvenanceLocalWorkspace, CreatedAt: now}, Score: 0.90}
	c2 := &SearchResult{Node: &MemoryNode{ID: "a2", Content: "chunk 2", Vector: vA, AuthorityTier: "TIER_1_ARCHITECTURE", Provenance: ProvenanceLocalWorkspace, CreatedAt: now}, Score: 0.88}
	c3 := &SearchResult{Node: &MemoryNode{ID: "b1", Content: "distinct insight", Vector: vB, AuthorityTier: "TIER_1_ARCHITECTURE", Provenance: ProvenanceLocalWorkspace, CreatedAt: now}, Score: 0.82}

	mmr := RerankResults([]*SearchResult{c1, c2, c3}, RerankConfig{
		MMRLambda: 0.65,
		Limit:     2,
		Now:       now,
	})
	if len(mmr) != 2 || mmr[0].Node.ID != "a1" || mmr[1].Node.ID != "b1" {
		t.Fatalf("expected MMR to select [a1, b1] for diversity, got [%s, %s]", mmr[0].Node.ID, mmr[1].Node.ID)
	}
}
