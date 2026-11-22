package mcp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/lenses"
)

func invokeRPC(t *testing.T, srv *Server, outBuf *bytes.Buffer, reqJSON string) JSONRPCMessage {
	t.Helper()
	outBuf.Reset()
	if err := srv.ServeSTDIO(context.Background(), strings.NewReader(reqJSON+"\n")); err != nil {
		t.Fatalf("ServeSTDIO failed: %v", err)
	}
	var msg JSONRPCMessage
	if err := json.Unmarshal(bytes.TrimSpace(outBuf.Bytes()), &msg); err != nil {
		t.Fatalf("decode JSON-RPC response failed: %v (raw=%s)", err, outBuf.String())
	}
	return msg
}

func TestMCP_InitializePromptsCapabilityAndPromptsLifecycle(t *testing.T) {
	srv, _, outBuf := newTestMCPServer(t)

	// 1. initialize must advertise prompts: {listChanged: false}
	initMsg := invokeRPC(t, srv, outBuf, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	if initMsg.Error != nil {
		t.Fatalf("initialize returned error: %+v", initMsg.Error)
	}
	var initResult struct {
		Capabilities struct {
			Tools   map[string]bool `json:"tools"`
			Prompts map[string]bool `json:"prompts"`
		} `json:"capabilities"`
	}
	if err := json.Unmarshal(initMsg.Result, &initResult); err != nil {
		t.Fatalf("unmarshal initialize result: %v", err)
	}
	if initResult.Capabilities.Prompts == nil {
		t.Fatalf("expected capabilities.prompts to be advertised, got: %s", string(initMsg.Result))
	}
	if lc, ok := initResult.Capabilities.Prompts["listChanged"]; !ok || lc {
		t.Fatalf("expected capabilities.prompts.listChanged=false, got: %+v", initResult.Capabilities.Prompts)
	}

	// 2. prompts/list must expose the 3 canonical prompts
	listMsg := invokeRPC(t, srv, outBuf, `{"jsonrpc":"2.0","id":2,"method":"prompts/list","params":{}}`)
	if listMsg.Error != nil {
		t.Fatalf("prompts/list returned error: %+v", listMsg.Error)
	}
	var listResult struct {
		Prompts []PromptDef `json:"prompts"`
	}
	if err := json.Unmarshal(listMsg.Result, &listResult); err != nil {
		t.Fatalf("unmarshal prompts/list result: %v", err)
	}

	wantPrompts := map[string]bool{
		"coppermind:security-audit": false,
		"coppermind:systems-audit":  false,
		"coppermind:drift-audit":    false,
	}
	for _, p := range listResult.Prompts {
		if _, ok := wantPrompts[p.Name]; ok {
			wantPrompts[p.Name] = true
		}
		if p.Name == "coppermind:security-audit" {
			gotArgs := make(map[string]bool)
			for _, a := range p.Arguments {
				gotArgs[a.Name] = true
			}
			for _, reqArg := range []string{"target_id", "file_path", "content", "project"} {
				if !gotArgs[reqArg] {
					t.Errorf("prompt %s missing expected optional argument %q", p.Name, reqArg)
				}
			}
		}
	}
	for name, seen := range wantPrompts {
		if !seen {
			t.Fatalf("prompts/list missing canonical prompt %q", name)
		}
	}

	// 3. prompts/get for all 3 prompts (bare + with inline content argument)
	for _, name := range []string{"coppermind:security-audit", "coppermind:systems-audit", "coppermind:drift-audit"} {
		getReq, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0",
			"id":      3,
			"method":  "prompts/get",
			"params": map[string]any{
				"name": name,
				"arguments": map[string]string{
					"file_path": "pkg/api/handler.go",
				},
			},
		})
		getMsg := invokeRPC(t, srv, outBuf, string(getReq))
		if getMsg.Error != nil {
			t.Fatalf("prompts/get(%s) error: %+v", name, getMsg.Error)
		}
		var getRes PromptGetResult
		if err := json.Unmarshal(getMsg.Result, &getRes); err != nil {
			t.Fatalf("unmarshal prompts/get(%s): %v", name, err)
		}
		if len(getRes.Messages) == 0 || !strings.Contains(getRes.Messages[0].Content.Text, "coppermind_lens_prepare") {
			t.Fatalf("expected prompts/get(%s) instructions referencing coppermind_lens_prepare, got: %+v", name, getRes)
		}
	}

	// 4. prompts/get with inline content returns fenced <untrusted_artifact> and live eval_token
	inlineReq, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      4,
		"method":  "prompts/get",
		"params": map[string]any{
			"name": "coppermind:security-audit",
			"arguments": map[string]string{
				"content":   `func (h *Handler) DeleteItem(w http.ResponseWriter, r *http.Request) { exec.Command("rm", r.URL.Path) }`,
				"file_path": "pkg/api/delete.go",
			},
		},
	})
	inlineMsg := invokeRPC(t, srv, outBuf, string(inlineReq))
	if inlineMsg.Error != nil {
		t.Fatalf("prompts/get with inline content failed: %+v", inlineMsg.Error)
	}
	var inlineRes PromptGetResult
	if err := json.Unmarshal(inlineMsg.Result, &inlineRes); err != nil {
		t.Fatalf("unmarshal inline prompts/get: %v", err)
	}
	if len(inlineRes.Messages) == 0 || !strings.Contains(inlineRes.Messages[0].Content.Text, "<untrusted_artifact") || !strings.Contains(inlineRes.Messages[0].Content.Text, "cmlens1.") {
		t.Fatalf("expected inline prompts/get to include <untrusted_artifact and eval_token, got: %+v", inlineRes)
	}

	// 5. prompts/get for unknown prompt returns JSON-RPC ErrCodeInvalidParams
	badPromptMsg := invokeRPC(t, srv, outBuf, `{"jsonrpc":"2.0","id":5,"method":"prompts/get","params":{"name":"coppermind:nonexistent"}}`)
	if badPromptMsg.Error == nil || badPromptMsg.Error.Code != ErrCodeInvalidParams {
		t.Fatalf("expected ErrCodeInvalidParams for unknown prompt, got: %+v", badPromptMsg)
	}
}

func TestMCP_LensPrepareAndSubmitRoundTripWithBLPRReceipt(t *testing.T) {
	srv, mgr, outBuf := newTestMCPServer(t)

	// Seed a sibling endpoint for differential security audit
	_, err := mgr.Remember(context.Background(), brain.RememberRequest{
		SessionID: "sess_01JLENSROUND",
		Category:  "code",
		Content:   `func (h *ItemHandler) GetItemHandler(w http.ResponseWriter, r *http.Request) { verifyTenant(r); returnItem(w) }`,
		Metadata:  map[string]string{"file_path": "pkg/api/get_item.go", "handler": "GetItemHandler"},
	})
	if err != nil {
		t.Fatalf("seed sibling failed: %v", err)
	}

	// Verify both new tools are listed in tools/list
	toolsMsg := invokeRPC(t, srv, outBuf, `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)
	if toolsMsg.Error != nil {
		t.Fatalf("tools/list failed: %+v", toolsMsg.Error)
	}
	var toolsList struct {
		Tools []ToolDef `json:"tools"`
	}
	if err := json.Unmarshal(toolsMsg.Result, &toolsList); err != nil {
		t.Fatalf("unmarshal tools/list: %v", err)
	}
	seenTools := map[string]bool{}
	for _, td := range toolsList.Tools {
		seenTools[td.Name] = true
	}
	if !seenTools["coppermind_lens_prepare"] || !seenTools["coppermind_lens_submit"] {
		t.Fatalf("expected coppermind_lens_prepare and coppermind_lens_submit in tools/list, got: %+v", seenTools)
	}

	// Start mock LOCKSMITH_SOCKET UDS signer to verify BLPR-v1 receipt signing on submit
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	sockDir, err := os.MkdirTemp("/tmp", "cm-lens-ls-*")
	if err != nil {
		t.Fatalf("mkdirtemp sockDir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	sockPath := filepath.Join(sockDir, "l.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, aErr := ln.Accept()
			if aErr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var req locksmithSignDSSERequest
				if dErr := json.NewDecoder(c).Decode(&req); dErr != nil {
					return
				}
				paeBytes, dErr := base64.StdEncoding.DecodeString(req.PAEB64)
				if dErr != nil {
					return
				}
				sig := ed25519.Sign(priv, paeBytes)
				_ = json.NewEncoder(c).Encode(map[string]string{
					"keyid": fmt.Sprintf("spiffe://bonjoski.local/session/%s", req.SessionID),
					"sig":   base64.StdEncoding.EncodeToString(sig),
				})
			}(conn)
		}
	}()

	receiptDir := filepath.Join(t.TempDir(), "receipts")
	t.Setenv("FABRIAL_RECEIPT_DIR", receiptDir)
	t.Setenv("LOCKSMITH_SOCKET", sockPath)

	// Step 1: Call coppermind_lens_prepare
	prepReq, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "coppermind_lens_prepare",
			"arguments": map[string]any{
				"lens":       "security-architect",
				"content":    `func (h *ItemHandler) DeleteItemHandler(w http.ResponseWriter, r *http.Request) { deleteItem(r.URL.Query().Get("id")) }`,
				"file_path":  "pkg/api/delete_item.go",
				"session_id": "sess_01JLENSROUND",
			},
		},
	})
	prepRes := invokeTool(t, srv, outBuf, string(prepReq))
	if prepRes.IsError || len(prepRes.Content) == 0 {
		t.Fatalf("coppermind_lens_prepare failed: %+v", prepRes)
	}
	var bundle lenses.PreparedLensBundle
	if err := json.Unmarshal([]byte(prepRes.Content[0].Text), &bundle); err != nil {
		t.Fatalf("unmarshal PreparedLensBundle: %v", err)
	}
	if bundle.Skipped || bundle.EvalToken == "" {
		t.Fatalf("expected prepared bundle with eval_token, got: %+v", bundle)
	}
	if !strings.Contains(bundle.UserPrompt, "<untrusted_artifact") || !strings.Contains(bundle.UserPrompt, "<sibling_endpoints>") {
		t.Fatalf("expected fenced artifact and sibling endpoints in user_prompt:\n%s", bundle.UserPrompt)
	}
	if bundle.SubmitTool != "coppermind_lens_submit" {
		t.Fatalf("expected submit_tool='coppermind_lens_submit', got %q", bundle.SubmitTool)
	}

	// Step 2: Host AI submits structured JSON findings with emit_receipt=true
	submitReq, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      3,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "coppermind_lens_submit",
			"arguments": map[string]any{
				"eval_token": bundle.EvalToken,
				"session_id": "sess_01JLENSROUND",
				"findings_json": map[string]any{
					"findings": []map[string]any{
						{
							"severity":              "high",
							"category":              "differential_auth",
							"entry_point":           "DeleteItemHandler",
							"sibling_inconsistency": "GetItemHandler calls verifyTenant(r); DeleteItemHandler omits it",
							"summary":               "IDOR cross-tenant deletion in DeleteItemHandler",
							"poc":                   "curl -X DELETE http://localhost:8080/items?id=victim-1",
						},
						{
							"severity":    "critical",
							"category":    "differential_auth",
							"entry_point": "DeleteItemHandler",
							"summary":     "Speculative finding without executable PoC",
							"poc":         "N/A",
						},
					},
				},
				"emit_receipt": true,
			},
		},
	})
	subRes := invokeTool(t, srv, outBuf, string(submitReq))
	if subRes.IsError || len(subRes.Content) == 0 {
		t.Fatalf("coppermind_lens_submit failed: %+v", subRes)
	}
	var parsedSub lenses.HostEvalSubmissionResult
	if err := json.Unmarshal([]byte(subRes.Content[0].Text), &parsedSub); err != nil {
		t.Fatalf("unmarshal HostEvalSubmissionResult: %v", err)
	}
	if parsedSub.AcceptedCount != 2 || parsedSub.DemotedNoPoCCount != 1 || parsedSub.DeduplicatedCount != 0 {
		t.Fatalf("unexpected submission counts: %+v", parsedSub)
	}
	if !strings.HasPrefix(parsedSub.ReceiptID, "rcpt_") {
		t.Fatalf("expected BLPR-v1 receipt_id starting with rcpt_, got %q", parsedSub.ReceiptID)
	}

	// Verify signed BLPR-v1 DSSE envelope on disk
	entries, err := os.ReadDir(receiptDir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected 1 receipt file in %s, got %d (err=%v)", receiptDir, len(entries), err)
	}
	rawReceipt, err := os.ReadFile(filepath.Join(receiptDir, entries[0].Name()))
	if err != nil {
		t.Fatalf("read receipt: %v", err)
	}
	var env DSSEEnvelope
	if err := json.Unmarshal(rawReceipt, &env); err != nil {
		t.Fatalf("unmarshal DSSE envelope: %v", err)
	}
	stmt, err := VerifyEnvelope(&env, pub)
	if err != nil {
		t.Fatalf("VerifyEnvelope failed: %v", err)
	}
	if !stmt.Predicate.Proven || stmt.Predicate.ReceiptID != parsedSub.ReceiptID {
		t.Fatalf("unexpected BLPR-v1 statement: %+v", stmt.Predicate)
	}
	if stmt.Predicate.Claims["lens"] != "security-architect" {
		t.Fatalf("expected claims.lens='security-architect', got %v", stmt.Predicate.Claims["lens"])
	}

	// Verify persisted observations in SQLite have Derived=true and AuthorityTier=TIER_3_DERIVED
	obsList, err := mgr.ListObservations(context.Background(), "sess_01JLENSROUND", "security-architect", "open", "info", 10)
	if err != nil {
		t.Fatalf("ListObservations failed: %v", err)
	}
	if len(obsList) != 2 {
		t.Fatalf("expected 2 persisted derived observations, got %d", len(obsList))
	}
	for _, obs := range obsList {
		if !obs.Derived || obs.AuthorityTier != lenses.TierDerivedObservation {
			t.Fatalf("observation %s violated derived/tier invariants: derived=%v tier=%q", obs.ID, obs.Derived, obs.AuthorityTier)
		}
	}
}

func TestMCP_LensSubmitRejectsForgedReplayedAndInvalidJSONWithUBMCPv1(t *testing.T) {
	srv, _, outBuf := newTestMCPServer(t)

	// 1. Benign content skipped by prefilter
	benignReq := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"coppermind_lens_prepare","arguments":{"lens":"security-architect","content":"func Add(a, b int) int { return a + b }"}}}`
	benignRes := invokeTool(t, srv, outBuf, benignReq)
	if benignRes.IsError {
		t.Fatalf("expected benign skip without error, got: %+v", benignRes)
	}
	var skippedBundle lenses.PreparedLensBundle
	if err := json.Unmarshal([]byte(benignRes.Content[0].Text), &skippedBundle); err != nil {
		t.Fatalf("unmarshal skipped bundle: %v", err)
	}
	if !skippedBundle.Skipped || skippedBundle.SkipReason != lenses.SkipReasonPrefilterNoSinks {
		t.Fatalf("expected prefilter_no_sinks skip, got: %+v", skippedBundle)
	}

	// 2. Forged eval_token -> UB-MCP-v1 error with ExitCodePolicyDeny (10)
	forgedReq := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"coppermind_lens_submit","arguments":{"eval_token":"cmlens1.Zm9yZ2Vk.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","findings_json":"{\"findings\":[]}"}}}`
	forgedRes := invokeTool(t, srv, outBuf, forgedReq)
	sc := assertValidUBMCPv1Error(t, &forgedRes, ExitCodePolicyDeny)
	if sc["code"] != "COPPERMIND_EVAL_TOKEN_DENY" {
		t.Fatalf("expected COPPERMIND_EVAL_TOKEN_DENY, got %v", sc["code"])
	}

	// 3. Prepare a valid token, submit invalid JSON -> UB-MCP-v1 error with ExitCodePolicyDeny (10)
	prepReq := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"coppermind_lens_prepare","arguments":{"lens":"security-architect","content":"func (h *H) Run(c string) { exec.Command(c) }","session_id":"sess_badjson"}}}`
	prepRes := invokeTool(t, srv, outBuf, prepReq)
	var b1 lenses.PreparedLensBundle
	_ = json.Unmarshal([]byte(prepRes.Content[0].Text), &b1)

	badJSONReq, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      4,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "coppermind_lens_submit",
			"arguments": map[string]any{
				"eval_token":    b1.EvalToken,
				"session_id":    "sess_badjson",
				"findings_json": "not valid json at all",
			},
		},
	})
	badJSONRes := invokeTool(t, srv, outBuf, string(badJSONReq))
	scBad := assertValidUBMCPv1Error(t, &badJSONRes, ExitCodePolicyDeny)
	if scBad["code"] != "COPPERMIND_LENS_INVALID_JSON" {
		t.Fatalf("expected COPPERMIND_LENS_INVALID_JSON, got %v", scBad["code"])
	}

	// 4. Replaying the same token (even with valid JSON) -> UB-MCP-v1 error with ExitCodePolicyDeny (10)
	replayReq, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      5,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "coppermind_lens_submit",
			"arguments": map[string]any{
				"eval_token":    b1.EvalToken,
				"session_id":    "sess_badjson",
				"findings_json": `{"findings":[]}`,
			},
		},
	})
	replayRes := invokeTool(t, srv, outBuf, string(replayReq))
	scReplay := assertValidUBMCPv1Error(t, &replayRes, ExitCodePolicyDeny)
	if scReplay["code"] != "COPPERMIND_EVAL_TOKEN_DENY" {
		t.Fatalf("expected COPPERMIND_EVAL_TOKEN_DENY on replay, got %v", scReplay["code"])
	}
}
