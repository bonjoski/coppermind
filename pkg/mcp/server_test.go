package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/embedding"
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
