package brain_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/embedding"
	"github.com/bonjoski/coppermind/pkg/scratchpad"
	"github.com/bonjoski/coppermind/pkg/storage/sqlite"
)

func TestManager_SecretQuarantine(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "quarantine_test.db")

	store, err := sqlite.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to init store: %v", err)
	}
	defer store.Close()

	embedder := embedding.NewLocalHashEmbedder(128)
	sp := scratchpad.NewMemoryScratchpad()
	mgr := brain.NewManager(store, embedder, sp)

	// 1. Attempt to store a raw private key -> MUST be rejected fail-closed
	rawPrivKey := `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y123456789abcdefghijklmnopqrstuvwxyz
-----END RSA PRIVATE KEY-----`
	_, err = mgr.Remember(ctx, brain.RememberRequest{
		Content:  rawPrivKey,
		Category: "secrets",
	})
	if err == nil {
		t.Fatalf("expected Remember to reject raw private key, but it succeeded")
	}
	if !strings.Contains(err.Error(), "security policy violation") {
		t.Errorf("expected security policy violation error, got: %v", err)
	}

	// 2. Attempt to store text with an embedded API key -> MUST be redacted
	embeddedKey := "Failed connecting to OpenAI with key sk-proj-1234567890abcdef1234567890abcdef on endpoint /chat"
	node, err := mgr.Remember(ctx, brain.RememberRequest{
		Content:  embeddedKey,
		Category: "incident",
	})
	if err != nil {
		t.Fatalf("unexpected error storing text: %v", err)
	}

	if strings.Contains(node.Content, "sk-proj-1234567890abcdef1234567890abcdef") {
		t.Errorf("critical failure: raw API key was not redacted from node content: %s", node.Content)
	}
	if !strings.Contains(node.Content, "[REDACTED_OPENAI_KEY]") {
		t.Errorf("expected [REDACTED_OPENAI_KEY] in content, got: %s", node.Content)
	}
	if node.Metadata["redacted_secrets"] != "1" {
		t.Errorf("expected metadata redacted_secrets=1, got: %v", node.Metadata)
	}

	// 3. Verify that scratchpad also redacts credentials
	err = sp.Set(ctx, "temp_key", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgN_pGFrpQ1_8b_PqK_placeholder", 0)
	if err != nil {
		t.Fatalf("unexpected scratchpad set error: %v", err)
	}
	val, ok := sp.Get(ctx, "temp_key")
	if !ok {
		t.Fatalf("expected key to exist")
	}
	if strings.Contains(val, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9") {
		t.Errorf("critical failure: JWT was not redacted from scratchpad: %s", val)
	}
	if !strings.Contains(val, "[REDACTED_JWT]") {
		t.Errorf("expected [REDACTED_JWT] in scratchpad value, got: %s", val)
	}
}
