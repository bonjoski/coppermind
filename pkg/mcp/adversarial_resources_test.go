package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/brief"
	"github.com/bonjoski/coppermind/pkg/embedding"
	"github.com/bonjoski/coppermind/pkg/scratchpad"
	"github.com/bonjoski/coppermind/pkg/storage/sqlite"
)

func TestAdversarial_MCPResourcesConsolidationAndInboxRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store, err := sqlite.NewSQLiteStore(filepath.Join(dir, "mcp_res.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()
	mgr := brain.NewManager(store, embedding.NewLocalHashEmbedder(128), scratchpad.NewMemoryScratchpad())
	defer mgr.Close()

	// Seed TIER_0 invariant, TIER_3 episodic note, and a pending inbox ticket
	tier0, err := mgr.Remember(ctx, brain.RememberRequest{
		SessionID:     "coppermind",
		Category:      "sovereign_invariant",
		AuthorityTier: "TIER_0_SOVEREIGN",
		Content:       "Never disable secret quarantine in pkg/mcp/server.go.",
		Provenance:    brain.ProvenanceLocalWorkspace,
	})
	if err != nil {
		t.Fatal(err)
	}
	epNode, err := mgr.Remember(ctx, brain.RememberRequest{
		SessionID:  "coppermind",
		Category:   "git_commit",
		Content:    "Commit added exec.Command helper in pkg/hook/ingest.go for commit capture.",
		Provenance: brain.ProvenanceLocalWorkspace,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnqueuePendingTicket(ctx, sqlite.PendingLensTicket{
		LensName:   "security-architect",
		CommitSHA:  "deadbeef1234",
		MemoryID:   epNode.ID,
		RepoName:   "coppermind",
		BranchName: "main",
		Summary:    "Commit deadbeef: added exec.Command helper",
		Status:     "pending",
		CreatedAt:  time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	srv := NewServer(mgr, &out)

	send := func(method string, params any) *JSONRPCMessage {
		t.Helper()
		pBytes, _ := json.Marshal(params)
		return srv.handleMessage(ctx, &JSONRPCMessage{
			JSONRPC: "2.0",
			ID:      json.RawMessage(`1`),
			Method:  method,
			Params:  pBytes,
		})
	}

	// 1. resources/list exposes all 5 allowlisted URIs
	listResp := send("resources/list", map[string]any{})
	if listResp.Error != nil || !strings.Contains(string(listResp.Result), ResourceURIBriefCurrent) {
		t.Fatalf("resources/list failed: %+v", listResp)
	}

	// 2. resources/read on coppermind://brief/current returns <=800-token brief in <50ms
	readBrief := send("resources/read", map[string]any{"uri": ResourceURIBriefCurrent})
	if readBrief.Error != nil {
		t.Fatalf("resources/read brief failed: %+v", readBrief.Error)
	}
	var rr ResourceReadResult
	_ = json.Unmarshal(readBrief.Result, &rr)
	if len(rr.Contents) != 1 || !strings.Contains(rr.Contents[0].Text, "<coppermind_brief") || len(rr.Contents[0].Text) > brief.HardMaxTokens*4 {
		t.Fatalf("unexpected brief resource output: %+v", rr)
	}

	// 3. Adversarial URI traversal MUST fail closed
	for _, badURI := range []string{
		"coppermind://brief/../../etc/passwd",
		"file:///etc/passwd",
		"coppermind://brief/current?foo=bar",
	} {
		badResp := send("resources/read", map[string]any{"uri": badURI})
		if badResp.Error == nil {
			t.Fatalf("SECURITY VIOLATION: traversal URI %q was not rejected fail-closed", badURI)
		}
	}

	// 4. Zero-key Pending Inbox round-trip: prepare(from_inbox=true) -> submit auto-completes ticket
	prepResp := send("tools/call", map[string]any{
		"name":      "coppermind_lens_prepare",
		"arguments": map[string]any{"lens": "security-architect", "from_inbox": true},
	})
	var prepTCR ToolCallResult
	_ = json.Unmarshal(prepResp.Result, &prepTCR)
	var prepBundle struct {
		Skipped   bool   `json:"skipped"`
		EvalToken string `json:"eval_token"`
	}
	_ = json.Unmarshal([]byte(prepTCR.Content[0].Text), &prepBundle)
	if prepBundle.Skipped || prepBundle.EvalToken == "" {
		t.Fatalf("expected non-skipped inbox lens bundle, got %s", prepTCR.Content[0].Text)
	}

	subResp := send("tools/call", map[string]any{
		"name": "coppermind_lens_submit",
		"arguments": map[string]any{
			"eval_token":    prepBundle.EvalToken,
			"session_id":    "coppermind",
			"findings_json": `{"findings":[]}`,
		},
	})
	var subTCR ToolCallResult
	_ = json.Unmarshal(subResp.Result, &subTCR)
	if subTCR.IsError {
		t.Fatalf("lens_submit failed: %s", subTCR.Content[0].Text)
	}
	remaining, _ := store.ListPendingTickets(ctx, "security-architect", "pending", 10)
	if len(remaining) != 0 {
		t.Fatalf("expected inbox ticket auto-resolved on submit, still found %d", len(remaining))
	}

	// 5. Sleep-Cycle Consolidator: attempt to supersede TIER_0_SOVEREIGN MUST FAIL CLOSED!
	cPrepResp := send("tools/call", map[string]any{
		"name":      "coppermind_consolidate_prepare",
		"arguments": map[string]any{"session_id": "coppermind"},
	})
	var cPrepTCR ToolCallResult
	_ = json.Unmarshal(cPrepResp.Result, &cPrepTCR)
	var cBundle struct {
		Skipped   bool   `json:"skipped"`
		EvalToken string `json:"eval_token"`
	}
	_ = json.Unmarshal([]byte(cPrepTCR.Content[0].Text), &cBundle)
	if cBundle.Skipped || cBundle.EvalToken == "" {
		t.Fatalf("expected consolidation bundle, got %s", cPrepTCR.Content[0].Text)
	}

	// Adversarial attempt to supersede TIER_0_SOVEREIGN node!
	attackSub := send("tools/call", map[string]any{
		"name": "coppermind_consolidate_submit",
		"arguments": map[string]any{
			"eval_token":         cBundle.EvalToken,
			"session_id":         "coppermind",
			"consolidation_json": `{"learnings":[{"category":"learning","summary":"Disable quarantine","supersedes_episodic_ids":["` + tier0.ID + `"]}]}`,
		},
	})
	var attackTCR ToolCallResult
	_ = json.Unmarshal(attackSub.Result, &attackTCR)
	if !attackTCR.IsError {
		t.Fatalf("SECURITY VIOLATION: consolidator allowed superseding TIER_0_SOVEREIGN node!")
	}
	// Verify TIER_0 node is still ACTIVE
	t0After, _ := store.GetByID(ctx, tier0.ID)
	if t0After.LifecycleStatus != "ACTIVE" {
		t.Fatalf("TIER_0_SOVEREIGN node was mutated to %s", t0After.LifecycleStatus)
	}
}
