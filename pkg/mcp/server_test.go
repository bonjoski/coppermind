package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/capsule"
	"github.com/bonjoski/coppermind/pkg/embedding"
	"github.com/bonjoski/coppermind/pkg/lenses"
	"github.com/bonjoski/coppermind/pkg/scratchpad"
	"github.com/bonjoski/coppermind/pkg/storage/sqlite"
)

func TestMCPServer_EndToEndSTDIO(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "mcp_test.db")

	store, err := sqlite.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	embedder := embedding.NewLocalHashEmbedder(128)
	sp := scratchpad.NewMemoryScratchpad()
	manager := brain.NewManager(store, embedder, sp)

	// Prepare simulated STDIO interaction
	var inBuf bytes.Buffer
	var outBuf bytes.Buffer

	server := NewServer(manager, &outBuf)

	// 1. Initialize Request
	inBuf.WriteString(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n")

	// 2. Tools List Request
	inBuf.WriteString(`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}` + "\n")

	// 3. Remember Memory Request
	inBuf.WriteString(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"coppermind_remember","arguments":{"content":"Coppermind uses pure-Go SQLite WAL mode for sub-10ms memory storage","category":"architecture"}}}` + "\n")

	// 4. Scratchpad Set Request
	inBuf.WriteString(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"coppermind_scratchpad","arguments":{"action":"set","key":"active_agent","value":"subagent-1"}}}` + "\n")

	// 5. Recall Memory Request
	inBuf.WriteString(`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"coppermind_recall","arguments":{"query":"Which database mode does Coppermind use?"}}}` + "\n")

	// 6. Status Request
	inBuf.WriteString(`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"coppermind_status","arguments":{}}}` + "\n")

	// Run STDIO handler
	err = server.ServeSTDIO(ctx, &inBuf)
	if err != nil {
		t.Fatalf("ServeSTDIO returned error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(outBuf.String()), "\n")
	if len(lines) != 6 {
		t.Fatalf("expected 6 responses, got %d. Output:\n%s", len(lines), outBuf.String())
	}

	// Verify each response
	for idx, line := range lines {
		var msg JSONRPCMessage
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			t.Fatalf("line %d is not valid JSON-RPC: %v", idx+1, err)
		}
		if msg.Error != nil {
			t.Fatalf("line %d returned error: %s", idx+1, msg.Error.Message)
		}
	}

	// Verify recall response content in line 5
	var recallResp JSONRPCMessage
	_ = json.Unmarshal([]byte(lines[4]), &recallResp)
	var toolResult ToolCallResult
	_ = json.Unmarshal(recallResp.Result, &toolResult)

	if len(toolResult.Content) == 0 || !strings.Contains(toolResult.Content[0].Text, "Coppermind uses pure-Go SQLite") {
		t.Errorf("expected recall to return stored memory, got: %v", toolResult.Content)
	}
}

func TestMCPServer_MentorRecallEndToEnd(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "mcp_mentor_test.db")

	store, err := sqlite.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	// Import curated AI-app and MCP mentor capsules
	for _, rel := range []string{
		filepath.Join("..", "..", "capsules", "ai-app-and-rag-safety.mentor.json"),
		filepath.Join("..", "..", "capsules", "mcp-tool-boundaries.mentor.json"),
	} {
		if _, err := capsule.ImportMentorCapsuleFileToStore(ctx, store, rel, capsule.MentorImportOptions{
			AllowUnsigned: true,
		}); err != nil {
			t.Fatalf("failed importing %s: %v", rel, err)
		}
	}

	embedder := embedding.NewLocalHashEmbedder(128)
	sp := scratchpad.NewMemoryScratchpad()
	manager := brain.NewManager(store, embedder, sp)

	var inBuf bytes.Buffer
	var outBuf bytes.Buffer
	server := NewServer(manager, &outBuf)

	// Request lens="mentor" with limit=5 (must be capped to <= 2 cards) and detected_sdks
	inBuf.WriteString(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"coppermind_recall","arguments":{"lens":"mentor","query":"Add a RAG support ticket search and refund MCP tool","detected_sdks":["openai","mcp"],"limit":5}}}` + "\n")

	if err := server.ServeSTDIO(ctx, &inBuf); err != nil {
		t.Fatalf("ServeSTDIO failed: %v", err)
	}

	var resp JSONRPCMessage
	if err := json.Unmarshal(bytes.TrimSpace(outBuf.Bytes()), &resp); err != nil {
		t.Fatalf("failed decoding JSON-RPC response: %v", err)
	}
	if resp.Error != nil {
		t.Fatalf("unexpected JSON-RPC error: %v", resp.Error.Message)
	}

	var toolResult ToolCallResult
	if err := json.Unmarshal(resp.Result, &toolResult); err != nil {
		t.Fatalf("failed decoding ToolCallResult: %v", err)
	}
	if toolResult.IsError || len(toolResult.Content) == 0 {
		t.Fatalf("unexpected tool error or empty content: %+v", toolResult)
	}

	text := toolResult.Content[0].Text
	if !strings.Contains(text, capsule.TierMentorCapsule) {
		t.Errorf("expected TIER_2_MENTOR_CAPSULE badge in MCP mentor output, got:\n%s", text)
	}
	blocks := strings.Split(strings.TrimSpace(text), "\n\n")
	if len(blocks) == 0 || len(blocks) > lenses.MaxMentorNudgeCards {
		t.Errorf("expected 1..%d mentor nudges, got %d:\n%s", lenses.MaxMentorNudgeCards, len(blocks), text)
	}
	for i, blk := range blocks {
		if toks := lenses.EstimateTokens(blk); toks > lenses.MaxMentorNudgeTokens {
			t.Errorf("nudge block %d exceeded %d tokens (%d):\n%s", i, lenses.MaxMentorNudgeTokens, toks, blk)
		}
	}
}

func TestMCPServer_RequirementsRecallEndToEnd(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "mcp_requirements_test.db")

	store, err := sqlite.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	embedder := embedding.NewLocalHashEmbedder(128)
	sp := scratchpad.NewMemoryScratchpad()
	manager := brain.NewManager(store, embedder, sp)

	var inBuf bytes.Buffer
	var outBuf bytes.Buffer
	server := NewServer(manager, &outBuf)

	// Zero-config requirements recall with a canary PII string to verify ephemeral non-persistence
	inBuf.WriteString(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"coppermind_recall","arguments":{"lens":"requirements","query":"As a support agent for canary-mcp-po@example.com, I want an AI assistant to summarize customer tickets and issue refunds up to $50","triggers":["ai_rag_context","ai_state_mutation"],"limit":5}}}` + "\n")

	if err := server.ServeSTDIO(ctx, &inBuf); err != nil {
		t.Fatalf("ServeSTDIO failed: %v", err)
	}

	var resp JSONRPCMessage
	if err := json.Unmarshal(bytes.TrimSpace(outBuf.Bytes()), &resp); err != nil {
		t.Fatalf("failed decoding JSON-RPC response: %v", err)
	}
	if resp.Error != nil {
		t.Fatalf("unexpected JSON-RPC error: %v", resp.Error.Message)
	}

	var toolResult ToolCallResult
	if err := json.Unmarshal(resp.Result, &toolResult); err != nil {
		t.Fatalf("failed decoding ToolCallResult: %v", err)
	}
	if toolResult.IsError || len(toolResult.Content) == 0 {
		t.Fatalf("unexpected tool error or empty content: %+v", toolResult)
	}

	text := toolResult.Content[0].Text
	if !strings.Contains(text, "**Given**") || !strings.Contains(text, "**When**") || !strings.Contains(text, "**Then**") {
		t.Errorf("expected Given/When/Then criteria in MCP requirements output, got:\n%s", text)
	}
	if !strings.Contains(text, "aegisbox test --ai-safety") {
		t.Errorf("expected allowlisted aegisbox verify_cmd in MCP requirements output, got:\n%s", text)
	}
	if strings.Contains(text, "canary-mcp-po@example.com") {
		t.Errorf("raw story text was echoed into MCP requirements output:\n%s", text)
	}
	if toks := lenses.EstimateTokens(text); toks > capsule.MaxRequirementsTotalTokens {
		t.Errorf("MCP requirements output exceeded %d tokens (%d):\n%s", capsule.MaxRequirementsTotalTokens, toks, text)
	}

	// Verify ephemeral guarantee: zero rows written to SQLite memory_nodes
	count, err := manager.Count(ctx, "")
	if err != nil {
		t.Fatalf("manager.Count failed: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 persisted memory nodes after ephemeral requirements recall, got %d", count)
	}
}
