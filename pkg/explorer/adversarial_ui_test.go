package explorer

import (
	"bytes"
	"context"
	"errors"
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

func TestAdversarial_ExplorerLoopbackDNSRebindingAuthAndCSRF(t *testing.T) {
	dir := t.TempDir()
	store, err := sqlite.NewSQLiteStore(filepath.Join(dir, "ui.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	mgr := brain.NewManager(store, embedding.NewLocalHashEmbedder(128), scratchpad.NewMemoryScratchpad())
	defer mgr.Close()

	// 1. Non-loopback bind MUST fail closed
	if _, err := NewWebServer(mgr, WebOptions{ListenAddr: "0.0.0.0:8080"}); !errors.Is(err, ErrNonLoopbackRejected) {
		t.Fatalf("expected ErrNonLoopbackRejected for 0.0.0.0, got %v", err)
	}
	if _, err := NewWebServer(mgr, WebOptions{ListenAddr: "192.168.1.10:8080"}); !errors.Is(err, ErrNonLoopbackRejected) {
		t.Fatalf("expected ErrNonLoopbackRejected for LAN IP, got %v", err)
	}

	ws, err := NewWebServer(mgr, WebOptions{ListenAddr: "127.0.0.1:0", AllowCurate: false})
	if err != nil {
		t.Fatal(err)
	}
	h := ws.Handler()

	// 2. DNS rebinding probe (Host: evil.com) MUST return 403 even with valid token
	reqRebind := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9999/api/v1/health", nil)
	reqRebind.Host = "evil.com:9999"
	reqRebind.Header.Set("Authorization", "Bearer "+ws.Token())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, reqRebind)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("SECURITY VIOLATION: DNS rebinding Host header not blocked (status=%d)", rec.Code)
	}

	// 3. Missing auth token MUST return 401
	reqUnauth := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9999/api/v1/health", nil)
	reqUnauth.Host = "127.0.0.1:9999"
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, reqUnauth)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", rec.Code)
	}

	// 4. Valid authenticated read returns 200 + strict CSP
	reqOK := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9999/api/v1/health", nil)
	reqOK.Host = "127.0.0.1:9999"
	reqOK.Header.Set("Authorization", "Bearer "+ws.Token())
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, reqOK)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Header().Get("Content-Security-Policy"), "default-src 'self'") {
		t.Fatalf("expected 200 with strict CSP, got status=%d csp=%q", rec.Code, rec.Header().Get("Content-Security-Policy"))
	}

	// 5. Mutation blocked in read-only mode (403)
	reqMut := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:9999/api/v1/observations/obs_1/resolve", nil)
	reqMut.Host = "127.0.0.1:9999"
	reqMut.Header.Set("Authorization", "Bearer "+ws.Token())
	reqMut.Header.Set("X-Coppermind-CSRF", ws.CSRFToken())
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, reqMut)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 in read-only mode, got %d", rec.Code)
	}

	// 6. With --allow-curate, missing CSRF or cross-origin MUST still return 403
	wsCurate, _ := NewWebServer(mgr, WebOptions{ListenAddr: "127.0.0.1:0", AllowCurate: true})
	reqBadCSRF := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:9999/api/v1/observations/obs_1/resolve", nil)
	reqBadCSRF.Host = "127.0.0.1:9999"
	reqBadCSRF.Header.Set("Authorization", "Bearer "+wsCurate.Token())
	rec = httptest.NewRecorder()
	wsCurate.Handler().ServeHTTP(rec, reqBadCSRF)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 without CSRF token, got %d", rec.Code)
	}

	// 7. TUI basic navigation, Merkle verify, reindex & health render
	var out bytes.Buffer
	tui := NewTUI(mgr, strings.NewReader("health\ninbox\nverify default\nreindex\nq\n"), &out)
	if err := tui.Run(context.Background()); err != nil {
		t.Fatalf("TUI run failed: %v", err)
	}
	if !strings.Contains(out.String(), "Active Embedder") ||
		!strings.Contains(out.String(), "Pending Zero-Key Lens Inbox") ||
		!strings.Contains(out.String(), "Merkle chain INTACT") ||
		!strings.Contains(out.String(), "Reindexed") {
		t.Fatalf("unexpected TUI output:\n%s", out.String())
	}
}
