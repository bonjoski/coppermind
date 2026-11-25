package explorer

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/embedding"
	"github.com/bonjoski/coppermind/pkg/scratchpad"
	"github.com/bonjoski/coppermind/pkg/storage/sqlite"
)

func TestExplorerWebAndTUIScopes(t *testing.T) {
	dir := t.TempDir()
	store, err := sqlite.NewSQLiteStore(filepath.Join(dir, "exp_scopes.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()
	mgr := brain.NewManager(store, embedding.NewLocalHashEmbedder(128), scratchpad.NewMemoryScratchpad())
	defer mgr.Close()

	for _, item := range []struct{ sc, content string }{
		{"platform", "Platform logging rule"},
		{"platform/payments/webhooks", "Stripe webhook HMAC signature rule"},
		{"platform/auth", "OIDC JWKS rotation rule"},
	} {
		if _, err := mgr.Remember(ctx, brain.RememberRequest{
			Category:   "architecture",
			Scope:      item.sc,
			Content:    item.content,
			Provenance: brain.ProvenanceLocalWorkspace,
		}); err != nil {
			t.Fatal(err)
		}
	}

	ws, err := NewWebServer(mgr, WebOptions{ListenAddr: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	h := ws.Handler()

	// 1. GET /api/v1/scopes returns hierarchical scope list
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9999/api/v1/scopes", nil)
	req.Host = "127.0.0.1:9999"
	req.Header.Set("Authorization", "Bearer "+ws.Token())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "platform/payments/webhooks") {
		t.Fatalf("unexpected /api/v1/scopes response: code=%d body=%s", rec.Code, rec.Body.String())
	}

	// 2. GET /api/v1/search?q=rule&scope=platform/payments/webhooks excludes platform/auth
	sReq := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9999/api/v1/search?q=rule&scope=platform/payments/webhooks", nil)
	sReq.Host = "127.0.0.1:9999"
	sReq.Header.Set("Authorization", "Bearer "+ws.Token())
	sRec := httptest.NewRecorder()
	h.ServeHTTP(sRec, sReq)
	if sRec.Code != http.StatusOK {
		t.Fatalf("unexpected /api/v1/search code=%d body=%s", sRec.Code, sRec.Body.String())
	}
	if strings.Contains(sRec.Body.String(), "OIDC JWKS") {
		t.Fatalf("SECURITY VIOLATION: sibling scope leaked in explorer search: %s", sRec.Body.String())
	}

	// 3. Invalid scope fails closed with 400 Bad Request
	badReq := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9999/api/v1/timeline?scope=../etc", nil)
	badReq.Host = "127.0.0.1:9999"
	badReq.Header.Set("Authorization", "Bearer "+ws.Token())
	badRec := httptest.NewRecorder()
	h.ServeHTTP(badRec, badReq)
	if badRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid scope in timeline, got %d", badRec.Code)
	}

	// 4. TUI 'scopes' command lists scopes cleanly
	var out bytes.Buffer
	tui := NewTUI(mgr, strings.NewReader("scopes\nq\n"), &out)
	if err := tui.Run(ctx); err != nil {
		t.Fatalf("TUI run failed: %v", err)
	}
	if !strings.Contains(out.String(), "platform/payments/webhooks") {
		t.Fatalf("TUI scopes output missing scope: %s", out.String())
	}
	_ = json.Valid(rec.Body.Bytes())
}
