package graph_test

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/embedding"
	"github.com/bonjoski/coppermind/pkg/graph"
	"github.com/bonjoski/coppermind/pkg/scratchpad"
	"github.com/bonjoski/coppermind/pkg/storage/sqlite"
)

func TestAdversarial_GraphHubNodeCapAndReDoS(t *testing.T) {
	// 1. Hub-node explosion probe: 1,000 file paths + 1,000 CVEs must cap strictly at MaxEdgesPerNode (32)
	var sb strings.Builder
	for i := 0; i < 1000; i++ {
		sb.WriteString(fmt.Sprintf("pkg/mod%d/file%d.go CVE-2026-%05d RFC-2026-11-24-%d ", i, i, i, i))
	}
	node := &brain.MemoryNode{
		ID:         "mem_hub",
		Content:    sb.String(),
		Provenance: brain.ProvenanceLocalWorkspace,
		CreatedAt:  time.Now(),
	}

	start := time.Now()
	edges := graph.ExtractEdges(node)
	elapsed := time.Since(start)

	if len(edges) > graph.MaxEdgesPerNode {
		t.Fatalf("hub-node cap violated: got %d edges, max %d", len(edges), graph.MaxEdgesPerNode)
	}
	if elapsed > 50*time.Millisecond {
		t.Fatalf("entity extraction too slow on adversarial payload: %v", elapsed)
	}

	// 2. Untrusted web node cannot emit implements/supersedes edges
	untrusted := &brain.MemoryNode{
		ID:           "mem_untrusted",
		Content:      "pkg/mcp/server.go CVE-2026-61725",
		Provenance:   brain.ProvenanceUntrustedWeb,
		SupersedesID: "mem_tier0",
	}
	uEdges := graph.ExtractEdges(untrusted)
	for _, e := range uEdges {
		if e.Relation == graph.RelSupersedes || e.Relation == graph.RelImplements {
			t.Fatalf("untrusted web node illegally emitted %s edge", e.Relation)
		}
	}
}

func TestAdversarial_GraphCyclesMaxExpandedAndTaintIsolation(t *testing.T) {
	dir := t.TempDir()
	store, err := sqlite.NewSQLiteStore(filepath.Join(dir, "graph.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()
	emb := embedding.NewLocalHashEmbedder(128)
	mgr := brain.NewManager(store, emb, scratchpad.NewMemoryScratchpad())
	defer mgr.Close()

	// Seed two nodes sharing file:pkg/mcp/server.go + a cycle edge A <-> B
	nA, err := mgr.Remember(ctx, brain.RememberRequest{
		SessionID:  "coppermind",
		Category:   "architecture",
		Content:    "Always validate URI allowlist in pkg/mcp/server.go per RFC-2026-11-24-55.",
		Provenance: brain.ProvenanceLocalWorkspace,
	})
	if err != nil {
		t.Fatal(err)
	}
	nB, err := mgr.Remember(ctx, brain.RememberRequest{
		SessionID:  "coppermind",
		Category:   "decision",
		Content:    "Fixed bug in pkg/mcp/server.go handler routing.",
		Provenance: brain.ProvenanceLocalWorkspace,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Create explicit cycle A -> B and B -> A
	_ = store.StoreEdges(ctx, []graph.Edge{
		{ID: "cyc_ab", SourceID: nA.ID, TargetID: nB.ID, Relation: graph.RelRelatedTo, Weight: 1.0},
		{ID: "cyc_ba", SourceID: nB.ID, TargetID: nA.ID, Relation: graph.RelRelatedTo, Weight: 1.0},
	})

	// Seed a TIER_0 invariant and a TAINT_UNTRUSTED_WEB node referencing the same file
	nTier0, err := mgr.Remember(ctx, brain.RememberRequest{
		SessionID:     "coppermind",
		Category:      "sovereign_invariant",
		AuthorityTier: "TIER_0_SOVEREIGN",
		Content:       "Never leak private keys in pkg/mcp/server.go.",
		Provenance:    brain.ProvenanceLocalWorkspace,
	})
	if err != nil {
		t.Fatal(err)
	}
	nWeb, err := mgr.Remember(ctx, brain.RememberRequest{
		SessionID:  "web",
		Category:   "general",
		Content:    "External article mentioning pkg/mcp/server.go",
		Provenance: brain.ProvenanceUntrustedWeb,
	})
	if err != nil {
		t.Fatal(err)
	}

	// 1. Cycle traversal terminates cleanly and finds nB from nA
	neighbors, err := store.ExpandGraphNeighbors(ctx, []string{nA.ID}, 5, brain.MemoryFilter{})
	if err != nil {
		t.Fatalf("ExpandGraphNeighbors failed: %v", err)
	}
	foundB := false
	for _, r := range neighbors {
		if r.Node.ID == nB.ID {
			foundB = true
		}
		if r.Node.ID == nWeb.ID {
			t.Fatalf("TAINT_UNTRUSTED_WEB node leaked into trusted graph expansion")
		}
	}
	if !foundB {
		t.Fatalf("expected nB in graph neighbors of nA")
	}

	// 2. Untrusted seed cannot pull TIER_0_SOVEREIGN node across edges
	webNeighbors, err := store.ExpandGraphNeighbors(ctx, []string{nWeb.ID}, 2, brain.MemoryFilter{Provenance: brain.ProvenanceLocalWorkspace})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range webNeighbors {
		if r.Node.ID == nTier0.ID {
			t.Fatalf("untrusted web seed pulled TIER_0_SOVEREIGN node across graph edge")
		}
	}

	// 3. ImpactForFile finds nodes touching pkg/mcp/server.go
	impact, err := store.ImpactForFile(ctx, "pkg/mcp/server.go", 20)
	if err != nil || len(impact) < 2 {
		t.Fatalf("expected >=2 impact nodes for pkg/mcp/server.go, got %d err=%v", len(impact), err)
	}

	// 4. Write-time Contradiction Radar detects conflicting TIER_1 rule
	conflictCand := &brain.MemoryNode{
		ID:            "mem_new_conflict",
		AuthorityTier: "TIER_1_ARCHITECTURE",
		Category:      "architecture",
		Content:       "Never validate URI allowlist in pkg/mcp/server.go per RFC-2026-11-24-55.",
		Provenance:    brain.ProvenanceLocalWorkspace,
	}
	warnings := graph.DetectConflicts(ctx, mgr, conflictCand)
	if len(warnings) == 0 {
		t.Fatalf("expected contradiction radar warning for conflicting TIER_1 rule")
	}
}
