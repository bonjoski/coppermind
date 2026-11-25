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

func TestAdversarial_MCPHierarchicalScopesAndTreeResource(t *testing.T) {
	dir := t.TempDir()
	store, err := sqlite.NewSQLiteStore(filepath.Join(dir, "mcp_scopes.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()
	mgr := brain.NewManager(store, embedding.NewLocalHashEmbedder(128), scratchpad.NewMemoryScratchpad())
	defer mgr.Close()

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

	// 1. Store platform, payments, webhooks, and auth sibling via MCP coppermind_remember
	for _, item := range []struct {
		sc, cat, txt string
	}{
		{"platform", "architecture", "Platform baseline: propagate X-Request-ID header on all RPCs."},
		{"platform/payments", "architecture", "Payments rule: enforce 24h Idempotency-Key deduplication."},
		{"platform/payments/webhooks", "convention", "Webhook rule: validate Stripe-Signature over raw bytes."},
		{"platform/auth", "architecture", "Auth sibling secret: rotate OIDC JWKS every 30 days."},
	} {
		resp := send("tools/call", map[string]any{
			"name": "coppermind_remember",
			"arguments": map[string]any{
				"scope":    item.sc,
				"category": item.cat,
				"content":  item.txt,
			},
		})
		if resp.Error != nil {
			t.Fatalf("coppermind_remember(%s) error: %+v", item.sc, resp.Error)
		}
		var tcr ToolCallResult
		_ = json.Unmarshal(resp.Result, &tcr)
		if tcr.IsError {
			t.Fatalf("coppermind_remember(%s) failed: %+v", item.sc, tcr)
		}
	}

	// 2. Scoped recall inherits platform + payments + webhooks and excludes platform/auth sibling
	recResp := send("tools/call", map[string]any{
		"name": "coppermind_recall",
		"arguments": map[string]any{
			"query": "X-Request-ID Idempotency-Key Stripe-Signature OIDC JWKS",
			"scope": "platform/payments/webhooks",
			"limit": 10,
		},
	})
	var recTCR ToolCallResult
	_ = json.Unmarshal(recResp.Result, &recTCR)
	if recTCR.IsError || len(recTCR.Content) == 0 {
		t.Fatalf("scoped recall failed: %+v", recTCR)
	}
	txt := recTCR.Content[0].Text
	if !strings.Contains(txt, "Stripe-Signature") || !strings.Contains(txt, "X-Request-ID") {
		t.Fatalf("expected inherited platform + leaf memories in recall output, got:\n%s", txt)
	}
	if strings.Contains(txt, "OIDC JWKS") {
		t.Fatalf("SECURITY VIOLATION: sibling platform/auth leaked into MCP recall:\n%s", txt)
	}

	// 3. Adversarial invalid scope fails closed with UB-MCP-v1 isError + exit_code: 10
	badResp := send("tools/call", map[string]any{
		"name": "coppermind_recall",
		"arguments": map[string]any{
			"query": "test",
			"scope": "platform/../etc",
		},
	})
	var badTCR ToolCallResult
	_ = json.Unmarshal(badResp.Result, &badTCR)
	if !badTCR.IsError {
		t.Fatalf("SECURITY VIOLATION: malformed scope did not fail closed in MCP recall: %+v", badTCR)
	}

	// 4. resources/list exposes coppermind://scopes/tree and resources/read returns scope hierarchy
	listResp := send("resources/list", map[string]any{})
	if !strings.Contains(string(listResp.Result), ResourceURIScopesTree) {
		t.Fatalf("resources/list missing %s", ResourceURIScopesTree)
	}
	treeResp := send("resources/read", map[string]any{"uri": ResourceURIScopesTree})
	if treeResp.Error != nil {
		t.Fatalf("resources/read %s failed: %+v", ResourceURIScopesTree, treeResp.Error)
	}
	var rr ResourceReadResult
	_ = json.Unmarshal(treeResp.Result, &rr)
	if len(rr.Contents) != 1 || !strings.Contains(rr.Contents[0].Text, "platform/payments/webhooks") {
		t.Fatalf("unexpected scopes tree resource output: %+v", rr)
	}

	// 5. coppermind://brief/current reflects COPPERMIND_SCOPE safely in <coppermind_brief scope="...">
	t.Setenv("COPPERMIND_SCOPE", "platform/payments/webhooks")
	briefResp := send("resources/read", map[string]any{"uri": ResourceURIBriefCurrent})
	if briefResp.Error != nil {
		t.Fatalf("scoped brief resource failed: %+v", briefResp.Error)
	}
	var br ResourceReadResult
	_ = json.Unmarshal(briefResp.Result, &br)
	if len(br.Contents) != 1 || !strings.Contains(br.Contents[0].Text, `scope="platform/payments/webhooks"`) {
		t.Fatalf("expected scoped brief header, got: %+v", br)
	}
}
