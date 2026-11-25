package explorer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bonjoski/coppermind/pkg/authz"
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

func TestAdversarial_ExplorerV2_TimelineLineageProposalsAndSovereignDeleteGuard(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := sqlite.NewSQLiteStore(filepath.Join(dir, "ui_v2.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	mgr := brain.NewManager(store, embedding.NewLocalHashEmbedder(128), scratchpad.NewMemoryScratchpad())
	defer mgr.Close()

	// Seed TIER_0_SOVEREIGN invariant, superseded pair, PROPOSED learning, and noisy TIER_3 chunk
	sov, err := mgr.Remember(ctx, brain.RememberRequest{
		SessionID:     "default",
		Category:      "security",
		Content:       "Never disable GPG commit signing on release tags.",
		AuthorityTier: authz.TierName0Sovereign,
		Metadata:      map[string]string{"git_repo": "coppermind"},
	})
	if err != nil {
		t.Fatal(err)
	}
	v1, err := mgr.Remember(ctx, brain.RememberRequest{
		SessionID:     "default",
		Category:      "architecture",
		Content:       "Use SHA-256 hash embedder for local vector retrieval.",
		AuthorityTier: authz.TierName1Architecture,
		Metadata:      map[string]string{"git_repo": "coppermind"},
	})
	if err != nil {
		t.Fatal(err)
	}
	v2, err := mgr.Remember(ctx, brain.RememberRequest{
		SessionID:     "default",
		Category:      "architecture",
		Content:       "Upgrade local vector retrieval to CMVEC1 static neural embeddings.",
		AuthorityTier: authz.TierName1Architecture,
		SupersedesID:  v1.ID,
		Rationale:     "RFC-2026-11-24-55 pure-Go semantic upgrade",
		Metadata:      map[string]string{"git_repo": "coppermind"},
	})
	if err != nil {
		t.Fatal(err)
	}
	prop, err := mgr.Remember(ctx, brain.RememberRequest{
		SessionID:       "default",
		Category:        "decision",
		Content:         "Candidate cartridge insight pending review.",
		AuthorityTier:   authz.TierName2MentorCapsule,
		LifecycleStatus: string(authz.StatusProposed),
	})
	if err != nil {
		t.Fatal(err)
	}
	noisy, err := mgr.Remember(ctx, brain.RememberRequest{
		SessionID:     "default",
		Category:      "note",
		Content:       "Temporary scratch note to be deleted.",
		AuthorityTier: authz.TierName3Episodic,
		Metadata:      map[string]string{"git_repo": "other-repo"},
	})
	if err != nil {
		t.Fatal(err)
	}

	wsRO, _ := NewWebServer(mgr, WebOptions{ListenAddr: "127.0.0.1:0", AllowCurate: false})
	wsCur, _ := NewWebServer(mgr, WebOptions{ListenAddr: "127.0.0.1:0", AllowCurate: true})

	// 1. Timeline endpoint with repo filter
	reqTL := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9999/api/v1/timeline?repo=coppermind&limit=10", nil)
	reqTL.Host = "127.0.0.1:9999"
	reqTL.Header.Set("Authorization", "Bearer "+wsCur.Token())
	rec := httptest.NewRecorder()
	wsCur.Handler().ServeHTTP(rec, reqTL)
	if rec.Code != http.StatusOK {
		t.Fatalf("timeline failed: status=%d body=%s", rec.Code, rec.Body.String())
	}
	var tlResp struct {
		Count int `json:"count"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &tlResp)
	if tlResp.Count != 3 {
		t.Fatalf("expected 3 coppermind timeline items (sov, v1, v2), got %d", tlResp.Count)
	}

	// 2. Lineage endpoint walks v2 -> v1
	reqLin := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9999/api/v1/lineage/"+v2.ID, nil)
	reqLin.Host = "127.0.0.1:9999"
	reqLin.Header.Set("Authorization", "Bearer "+wsCur.Token())
	rec = httptest.NewRecorder()
	wsCur.Handler().ServeHTTP(rec, reqLin)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), v1.ID) {
		t.Fatalf("lineage failed to return ancestor %s: status=%d body=%s", v1.ID, rec.Code, rec.Body.String())
	}

	// 3. Proposals list & reject action
	reqProps := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9999/api/v1/proposals", nil)
	reqProps.Host = "127.0.0.1:9999"
	reqProps.Header.Set("Authorization", "Bearer "+wsCur.Token())
	rec = httptest.NewRecorder()
	wsCur.Handler().ServeHTTP(rec, reqProps)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), prop.ID) {
		t.Fatalf("expected proposal %s in /api/v1/proposals: %s", prop.ID, rec.Body.String())
	}

	reqRej := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:9999/api/v1/proposals/"+prop.ID+"/reject", nil)
	reqRej.Host = "127.0.0.1:9999"
	reqRej.Header.Set("Authorization", "Bearer "+wsCur.Token())
	reqRej.Header.Set("X-Coppermind-CSRF", wsCur.CSRFToken())
	rec = httptest.NewRecorder()
	wsCur.Handler().ServeHTTP(rec, reqRej)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "REJECTED") {
		t.Fatalf("proposal reject failed: status=%d body=%s", rec.Code, rec.Body.String())
	}

	// 4. DELETE blocked in read-only mode (403)
	reqDelRO := httptest.NewRequest(http.MethodDelete, "http://127.0.0.1:9999/api/v1/memories/"+noisy.ID, nil)
	reqDelRO.Host = "127.0.0.1:9999"
	reqDelRO.Header.Set("Authorization", "Bearer "+wsRO.Token())
	reqDelRO.Header.Set("X-Coppermind-CSRF", wsRO.CSRFToken())
	rec = httptest.NewRecorder()
	wsRO.Handler().ServeHTTP(rec, reqDelRO)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("SECURITY VIOLATION: DELETE allowed in read-only mode (status=%d)", rec.Code)
	}

	// 5. DELETE on TIER_0_SOVEREIGN MUST fail closed with 403 EVEN WITH --allow-curate + CSRF!
	reqDelSov := httptest.NewRequest(http.MethodDelete, "http://127.0.0.1:9999/api/v1/memories/"+sov.ID, nil)
	reqDelSov.Host = "127.0.0.1:9999"
	reqDelSov.Header.Set("Authorization", "Bearer "+wsCur.Token())
	reqDelSov.Header.Set("X-Coppermind-CSRF", wsCur.CSRFToken())
	rec = httptest.NewRecorder()
	wsCur.Handler().ServeHTTP(rec, reqDelSov)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("SECURITY VIOLATION: TIER_0_SOVEREIGN delete was not refused (status=%d)", rec.Code)
	}
	if stillThere, _ := store.GetByID(ctx, sov.ID); stillThere == nil {
		t.Fatalf("SECURITY VIOLATION: TIER_0_SOVEREIGN memory disappeared after refused delete")
	}

	// 6. DELETE on TIER_3 noisy chunk succeeds under --allow-curate + CSRF
	reqDelNoisy := httptest.NewRequest(http.MethodDelete, "http://127.0.0.1:9999/api/v1/memories/"+noisy.ID, nil)
	reqDelNoisy.Host = "127.0.0.1:9999"
	reqDelNoisy.Header.Set("Authorization", "Bearer "+wsCur.Token())
	reqDelNoisy.Header.Set("X-Coppermind-CSRF", wsCur.CSRFToken())
	rec = httptest.NewRecorder()
	wsCur.Handler().ServeHTTP(rec, reqDelNoisy)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 deleting noisy TIER_3 chunk, got %d: %s", rec.Code, rec.Body.String())
	}

	// 7. TUI timeline, lineage, and fail-closed sovereign delete
	var out bytes.Buffer
	tui := NewTUI(mgr, strings.NewReader("timeline 5\nlineage "+v2.ID+"\ndelete "+sov.ID+"\nq\n"), &out)
	if err := tui.Run(ctx); err != nil {
		t.Fatalf("TUI v2 failed: %v", err)
	}
	text := out.String()
	if !strings.Contains(text, "Episodic Timeline") ||
		!strings.Contains(text, "Supersession Lineage") ||
		!strings.Contains(text, "Refused fail-closed: TIER_0_SOVEREIGN") {
		t.Fatalf("unexpected TUI v2 output:\n%s", text)
	}
}
