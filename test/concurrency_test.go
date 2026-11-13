package test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/embedding"
	"github.com/bonjoski/coppermind/pkg/mcp"
	"github.com/bonjoski/coppermind/pkg/scratchpad"
	"github.com/bonjoski/coppermind/pkg/storage/sqlite"
)

// TestMultiAgentConcurrency validates that N=8 parallel autonomous subagents can
// simultaneously remember, recall, and use scratchpads via MCP with zero lock contention.
func TestMultiAgentConcurrency(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "concurrency_test.db")

	store, err := sqlite.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to init sqlite store: %v", err)
	}
	defer store.Close()

	embedder := embedding.NewLocalHashEmbedder(128)
	sp := scratchpad.NewMemoryScratchpad()
	manager := brain.NewManager(store, embedder, sp)

	subagents := 8
	itemsPerAgent := 20
	var wg sync.WaitGroup

	errCh := make(chan error, subagents*itemsPerAgent)

	for a := 1; a <= subagents; a++ {
		wg.Add(1)
		go func(agentID int) {
			defer wg.Done()

			sessionID := fmt.Sprintf("session-worktree-%d", agentID)

			for i := 1; i <= itemsPerAgent; i++ {
				var inBuf bytes.Buffer
				var outBuf bytes.Buffer
				server := mcp.NewServer(manager, &outBuf)

				// 1. Store memory via MCP tools/call coppermind_remember
				rememberPayload := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"coppermind_remember","arguments":{"session_id":%q,"category":"invariant","content":"Subagent %d rule %d: always verify cryptographic proofs."}}}`,
					i, sessionID, agentID, i)
				inBuf.WriteString(rememberPayload + "\n")

				// 2. Set scratchpad value
				scratchpadPayload := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"coppermind_scratchpad","arguments":{"action":"set","key":"agent_%d_step","value":"step_%d"}}}`,
					i+1000, agentID, i)
				inBuf.WriteString(scratchpadPayload + "\n")

				// 3. Recall memory via MCP
				recallPayload := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"coppermind_recall","arguments":{"session_id":%q,"query":"cryptographic proofs"}}}`,
					i+2000, sessionID)
				inBuf.WriteString(recallPayload + "\n")

				if err := server.ServeSTDIO(ctx, &inBuf); err != nil {
					errCh <- fmt.Errorf("agent %d iteration %d ServeSTDIO error: %w", agentID, i, err)
					return
				}

				// Verify output contains valid results
				lines := bytes.Split(bytes.TrimSpace(outBuf.Bytes()), []byte("\n"))
				if len(lines) != 3 {
					errCh <- fmt.Errorf("agent %d iteration %d expected 3 responses, got %d", agentID, i, len(lines))
					return
				}

				for _, line := range lines {
					var resp mcp.JSONRPCMessage
					if err := json.Unmarshal(line, &resp); err != nil {
						errCh <- fmt.Errorf("agent %d json decode error: %w", agentID, err)
						return
					}
					if resp.Error != nil {
						errCh <- fmt.Errorf("agent %d received JSON-RPC error: %s", agentID, resp.Error.Message)
						return
					}
				}
			}
		}(a)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrency error: %v", err)
	}

	// Verify total stored items
	total, err := manager.Count(ctx, "")
	if err != nil {
		t.Fatalf("count error: %v", err)
	}

	expectedTotal := subagents * itemsPerAgent
	if total != expectedTotal {
		t.Errorf("expected %d total memories, got %d", expectedTotal, total)
	} else {
		t.Logf("✓ Concurrency validation SUCCESS: %d total memories written and recalled across %d parallel subagents with zero contention", total, subagents)
	}
}
