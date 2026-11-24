package brief

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/embedding"
	"github.com/bonjoski/coppermind/pkg/scratchpad"
	"github.com/bonjoski/coppermind/pkg/storage/sqlite"
)

func TestBrief_Strict800TokenCeilingAndContentSlots(t *testing.T) {
	dir := t.TempDir()
	store, err := sqlite.NewSQLiteStore(filepath.Join(dir, "brief.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()
	mgr := brain.NewManager(store, embedding.NewLocalHashEmbedder(128), scratchpad.NewMemoryScratchpad())
	defer mgr.Close()

	// Seed rich invariants, dead-end, scratchpad handoff, and pending inbox ticket
	for i := 0; i < 6; i++ {
		_, _ = mgr.Remember(ctx, brain.RememberRequest{
			SessionID:     "coppermind",
			Category:      "architecture",
			AuthorityTier: "TIER_1_ARCHITECTURE",
			Content:       "Invariant in pkg/mcp/server.go: always enforce strict URI allowlists and never expose arbitrary local files via MCP resources " + strings.Repeat("detail ", 30),
			Provenance:    brain.ProvenanceLocalWorkspace,
		})
	}
	_, _ = mgr.Remember(ctx, brain.RememberRequest{
		SessionID:  "coppermind",
		Category:   "dead_end",
		Content:    "Dead-end tried: synchronous access_count UPDATE on Recall caused WAL write contention under N=8; use async coalesced channel instead.",
		Provenance: brain.ProvenanceLocalWorkspace,
	})
	_ = mgr.Scratchpad().Set(ctx, "handoff:main", `{"agent_id":"a1","goal":"ship brief","next_step":"run tests"}`, 5*time.Minute)
	_ = store.EnqueuePendingTicket(ctx, sqlite.PendingLensTicket{
		LensName:  "security-architect",
		MemoryID:  "mem_1",
		Summary:   "Commit abc123 touched exec.Command",
		Status:    "pending",
		CreatedAt: time.Now(),
	})

	res, err := Compile(ctx, mgr, BriefRequest{
		MaxTokens:    HardMaxTokens,
		TouchedFiles: []string{"pkg/mcp/server.go"},
	})
	if err != nil {
		t.Fatalf("Compile failed: %v", err)
	}
	if res.EstimatedTokens > HardMaxTokens || len(res.Markdown) > HardMaxTokens*4 {
		t.Fatalf("brief exceeded hard 800-token ceiling: est=%d chars=%d", res.EstimatedTokens, len(res.Markdown))
	}
	if !strings.Contains(res.Markdown, "<coppermind_brief") || !strings.Contains(res.Markdown, "Invariants") || !strings.Contains(res.Markdown, "INBOX") {
		t.Fatalf("expected structured brief with invariants and inbox, got:\n%s", res.Markdown)
	}
}
