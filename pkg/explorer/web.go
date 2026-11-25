package explorer

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/bonjoski/coppermind/pkg/authz"
	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/scope"
	"github.com/bonjoski/coppermind/pkg/storage"
)

var (
	// ErrNonLoopbackRejected blocks binding the local Brain Explorer to non-loopback addresses.
	ErrNonLoopbackRejected = errors.New("explorer security policy violation: non-loopback listen address refused fail-closed (127.0.0.1 only)")
	hostLoopbackRe         = regexp.MustCompile(`^127\.0\.0\.1:\d{1,5}$`)
)

// WebOptions configures the strictly local 127.0.0.1 Brain Explorer HTTP server.
type WebOptions struct {
	ListenAddr  string // Defaults to "127.0.0.1:0" (ephemeral OS-assigned loopback port)
	AllowCurate bool   // Read-only by default; true enables POST resolve/approve with CSRF
}

// WebServer serves the zero-CDN, token-gated localhost Knowledge Graph & Timeline Explorer.
type WebServer struct {
	mgr         *brain.Manager
	graphStore  storage.GraphStore
	inboxStore  storage.InboxStore
	vecStore    storage.VectorAdminStore
	expStore    storage.ExplorerStore
	opts        WebOptions
	token       string
	csrfToken   string
	listener    net.Listener
	httpServer  *http.Server
	actualAddr  string
	bootstrapOK bool
}

// NewWebServer constructs a hardened loopback-only Brain Explorer server.
func NewWebServer(mgr *brain.Manager, opts WebOptions) (*WebServer, error) {
	if mgr == nil {
		return nil, fmt.Errorf("brain manager is required")
	}
	addr := strings.TrimSpace(opts.ListenAddr)
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host != "127.0.0.1" {
		return nil, fmt.Errorf("%w: %q", ErrNonLoopbackRejected, addr)
	}
	opts.ListenAddr = addr

	tokBytes := make([]byte, 32)
	if _, err := rand.Read(tokBytes); err != nil {
		return nil, err
	}
	csrfBytes := make([]byte, 24)
	if _, err := rand.Read(csrfBytes); err != nil {
		return nil, err
	}

	gStore, _ := mgr.Store().(storage.GraphStore)
	iStore, _ := mgr.Store().(storage.InboxStore)
	vStore, _ := mgr.Store().(storage.VectorAdminStore)
	eStore, _ := mgr.Store().(storage.ExplorerStore)
	ws := &WebServer{
		mgr:        mgr,
		graphStore: gStore,
		inboxStore: iStore,
		vecStore:   vStore,
		expStore:   eStore,
		opts:       opts,
		token:      hex.EncodeToString(tokBytes),
		csrfToken:  hex.EncodeToString(csrfBytes),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", ws.handleIndex)
	mux.HandleFunc("/api/v1/health", ws.handleHealth)
	mux.HandleFunc("/api/v1/search", ws.handleSearch)
	mux.HandleFunc("/api/v1/graph", ws.handleGraph)
	mux.HandleFunc("/api/v1/timeline", ws.handleTimeline)
	mux.HandleFunc("/api/v1/scopes", ws.handleScopes)
	mux.HandleFunc("/api/v1/lineage/", ws.handleLineage)
	mux.HandleFunc("/api/v1/memories/", ws.handleMemoryByID)
	mux.HandleFunc("/api/v1/observations", ws.handleObservations)
	mux.HandleFunc("/api/v1/proposals", ws.handleProposals)
	mux.HandleFunc("/api/v1/inbox", ws.handleInbox)
	mux.HandleFunc("/api/v1/verify/", ws.handleVerify)
	mux.HandleFunc("/api/v1/observations/", ws.handleObservationAction)
	mux.HandleFunc("/api/v1/proposals/", ws.handleProposalAction)

	ws.httpServer = &http.Server{
		Handler:           ws.securityMiddleware(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}
	return ws, nil
}

// Start binds strictly to 127.0.0.1 and begins serving in the background.
func (w *WebServer) Start() (string, error) {
	ln, err := net.Listen("tcp", w.opts.ListenAddr)
	if err != nil {
		return "", err
	}
	w.listener = ln
	w.actualAddr = ln.Addr().String()
	go func() {
		_ = w.httpServer.Serve(ln)
	}()
	return fmt.Sprintf("http://%s/?token=%s", w.actualAddr, w.token), nil
}

// Addr returns the bound 127.0.0.1:<port> address.
func (w *WebServer) Addr() string { return w.actualAddr }

// Token returns the 256-bit CSPRNG session token.
func (w *WebServer) Token() string { return w.token }

// CSRFToken returns the per-session CSRF header token.
func (w *WebServer) CSRFToken() string { return w.csrfToken }

// Handler returns the hardened http.Handler (useful for unit/adversarial testing).
func (w *WebServer) Handler() http.Handler { return w.httpServer.Handler }

// Close gracefully stops the localhost explorer server.
func (w *WebServer) Close(ctx context.Context) error {
	if w.httpServer == nil {
		return nil
	}
	return w.httpServer.Shutdown(ctx)
}

func (w *WebServer) securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		// 1. Anti-DNS-Rebinding: Host header MUST strictly match 127.0.0.1:<port>
		if !hostLoopbackRe.MatchString(r.Host) {
			http.Error(rw, "Forbidden: invalid Host header (DNS rebinding blocked)", http.StatusForbidden)
			return
		}
		if w.actualAddr != "" && r.Host != w.actualAddr {
			http.Error(rw, "Forbidden: host mismatch", http.StatusForbidden)
			return
		}

		// 2. Strict CSP & security headers (zero external scripts/styles/connections)
		rw.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'")
		rw.Header().Set("X-Frame-Options", "DENY")
		rw.Header().Set("X-Content-Type-Options", "nosniff")
		rw.Header().Set("Referrer-Policy", "no-referrer")

		// 3. One-time URL bootstrap token -> HttpOnly SameSite=Strict cookie + redirect stripping token
		if r.URL.Path == "/" && r.Method == http.MethodGet {
			if qTok := r.URL.Query().Get("token"); qTok != "" {
				if subtle.ConstantTimeCompare([]byte(qTok), []byte(w.token)) == 1 {
					http.SetCookie(rw, &http.Cookie{
						Name:     "coppermind_session",
						Value:    w.token,
						Path:     "/",
						HttpOnly: true,
						SameSite: http.SameSiteStrictMode,
					})
					http.Redirect(rw, r, "/", http.StatusFound)
					return
				}
				http.Error(rw, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}

		// 4. Require constant-time verified bearer header OR HttpOnly session cookie
		if !w.isAuthenticated(r) {
			http.Error(rw, "Unauthorized: valid Coppermind session token required", http.StatusUnauthorized)
			return
		}

		// 5. Mutating requests require --allow-curate + Origin pinning + CSRF header
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if !w.opts.AllowCurate {
				http.Error(rw, "Forbidden: explorer running in read-only mode (restart with --allow-curate)", http.StatusForbidden)
				return
			}
			if origin := r.Header.Get("Origin"); origin != "" {
				expectedOrigin := "http://" + r.Host
				if origin != expectedOrigin {
					http.Error(rw, "Forbidden: cross-origin mutation blocked", http.StatusForbidden)
					return
				}
			}
			csrf := r.Header.Get("X-Coppermind-CSRF")
			if subtle.ConstantTimeCompare([]byte(csrf), []byte(w.csrfToken)) != 1 {
				http.Error(rw, "Forbidden: missing or invalid X-Coppermind-CSRF header", http.StatusForbidden)
				return
			}
		}

		next.ServeHTTP(rw, r)
	})
}

func (w *WebServer) isAuthenticated(r *http.Request) bool {
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		cand := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		if subtle.ConstantTimeCompare([]byte(cand), []byte(w.token)) == 1 {
			return true
		}
	}
	if cookie, err := r.Cookie("coppermind_session"); err == nil {
		if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(w.token)) == 1 {
			return true
		}
	}
	return false
}

func writeJSON(rw http.ResponseWriter, status int, v any) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(status)
	_ = json.NewEncoder(rw).Encode(v)
}

func (w *WebServer) handleHealth(rw http.ResponseWriter, r *http.Request) {
	cnt, _ := w.mgr.Count(r.Context(), "")
	obs, _ := w.mgr.ListObservations(r.Context(), "", "", "open", "high", 100)
	var pendingCount int
	var cov *storage.VectorCoverage
	if w.inboxStore != nil {
		if tkts, err := w.inboxStore.ListPendingTickets(r.Context(), "", "pending", 100); err == nil {
			pendingCount = len(tkts)
		}
	}
	if w.vecStore != nil {
		cov, _ = w.vecStore.GetVectorCoverage(r.Context(), w.mgr.EmbedderModelName())
	}
	writeJSON(rw, http.StatusOK, map[string]any{
		"total_memories":   cnt,
		"open_high_obs":    len(obs),
		"pending_inbox":    pendingCount,
		"active_model":     w.mgr.EmbedderModelName(),
		"vector_coverage":  cov,
		"allow_curate":     w.opts.AllowCurate,
		"csrf_token":       w.csrfToken,
	})
}

func (w *WebServer) handleSearch(rw http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" {
		writeJSON(rw, http.StatusOK, map[string]any{"results": []any{}})
		return
	}
	hops := 1
	if hStr := r.URL.Query().Get("hops"); hStr != "" {
		if h, err := strconv.Atoi(hStr); err == nil && h >= 0 && h <= 2 {
			hops = h
		}
	}
	req := brain.RecallRequest{
		Query:   q,
		Hybrid:  true,
		Hops:    hops,
		Limit:   20,
		Explain: true,
	}
	if since := strings.TrimSpace(r.URL.Query().Get("since")); since != "" {
		t, err := brain.ResolveTemporalBound(since, "", time.Now().UTC())
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}
		req.CreatedAfter = &t
	}
	if rawScope := strings.TrimSpace(r.URL.Query().Get("scope")); rawScope != "" {
		normScope, err := scope.Normalize(rawScope)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}
		req.Scope = normScope
		req.ActiveScope = normScope
	}
	if rawMode := strings.TrimSpace(r.URL.Query().Get("scope_mode")); rawMode != "" {
		mode, err := scope.ParseMode(rawMode)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}
		req.ScopeMode = mode
	}
	res, err := w.mgr.Recall(r.Context(), req)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(rw, http.StatusOK, map[string]any{"count": len(res), "results": res})
}

func (w *WebServer) handleGraph(rw http.ResponseWriter, r *http.Request) {
	if w.graphStore == nil {
		writeJSON(rw, http.StatusOK, map[string]any{"nodes": []any{}, "edges": []any{}})
		return
	}
	center := strings.TrimSpace(r.URL.Query().Get("center"))
	nodes, edges, err := w.graphStore.GetGraphSubgraph(r.Context(), center, 100, 250)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(rw, http.StatusOK, map[string]any{"nodes": nodes, "edges": edges})
}

func (w *WebServer) handleTimeline(rw http.ResponseWriter, r *http.Request) {
	if w.expStore == nil {
		writeJSON(rw, http.StatusOK, map[string]any{"count": 0, "items": []any{}})
		return
	}
	limit := 50
	if lStr := strings.TrimSpace(r.URL.Query().Get("limit")); lStr != "" {
		if l, err := strconv.Atoi(lStr); err == nil && l > 0 {
			if l > 200 {
				l = 200
			}
			limit = l
		}
	}
	var sincePtr *time.Time
	if since := strings.TrimSpace(r.URL.Query().Get("since")); since != "" {
		t, err := brain.ResolveTemporalBound(since, "", time.Now().UTC())
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}
		sincePtr = &t
	}
	repoFilter := strings.TrimSpace(r.URL.Query().Get("repo"))
	var scopeFilter string
	var scopeMode scope.Mode
	if rawScope := strings.TrimSpace(r.URL.Query().Get("scope")); rawScope != "" {
		normScope, err := scope.Normalize(rawScope)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}
		scopeFilter = normScope
	}
	if rawMode := strings.TrimSpace(r.URL.Query().Get("scope_mode")); rawMode != "" {
		m, err := scope.ParseMode(rawMode)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}
		scopeMode = m
	}

	nodes, err := w.expStore.ListTimeline(r.Context(), storage.TimelineFilter{
		Since:     sincePtr,
		Repo:      repoFilter,
		Scope:     scopeFilter,
		ScopeMode: scopeMode,
		Limit:     limit,
	})
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	type timelineItem struct {
		ID              string            `json:"id"`
		SessionID       string            `json:"session_id"`
		Category        string            `json:"category"`
		Scope           string            `json:"scope,omitempty"`
		Content         string            `json:"content"`
		Metadata        map[string]string `json:"metadata,omitempty"`
		AuthorityTier   string            `json:"authority_tier"`
		LifecycleStatus string            `json:"lifecycle_status"`
		SupersedesID    string            `json:"supersedes_id,omitempty"`
		SupersededByID  string            `json:"superseded_by_id,omitempty"`
		CreatedAt       time.Time         `json:"created_at"`
	}

	items := make([]timelineItem, 0, len(nodes))
	for _, n := range nodes {
		items = append(items, timelineItem{
			ID:              n.ID,
			SessionID:       n.SessionID,
			Category:        n.Category,
			Scope:           n.Scope,
			Content:         n.Content,
			Metadata:        n.Metadata,
			AuthorityTier:   n.AuthorityTier,
			LifecycleStatus: n.LifecycleStatus,
			SupersedesID:    n.SupersedesID,
			SupersededByID:  n.SupersededByID,
			CreatedAt:       n.CreatedAt.UTC(),
		})
	}
	writeJSON(rw, http.StatusOK, map[string]any{"count": len(items), "items": items})
}

func (w *WebServer) handleScopes(rw http.ResponseWriter, r *http.Request) {
	if w.expStore == nil {
		writeJSON(rw, http.StatusOK, map[string]any{"count": 0, "scopes": []any{}})
		return
	}
	scopes, err := w.expStore.ListScopes(r.Context())
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(rw, http.StatusOK, map[string]any{"count": len(scopes), "scopes": scopes})
}

func (w *WebServer) handleLineage(rw http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/api/v1/lineage/"))
	if id == "" {
		http.Error(rw, "memory id required", http.StatusBadRequest)
		return
	}
	node, err := w.mgr.Store().GetByID(r.Context(), id)
	if err != nil || node == nil {
		http.Error(rw, "memory not found", http.StatusNotFound)
		return
	}
	var ancestors []*brain.MemoryNode
	var audit []*storage.SupersessionAudit
	var edges any
	if w.expStore != nil {
		ancestors, audit, _ = w.expStore.GetLineage(r.Context(), id)
	}
	if w.graphStore != nil {
		edges, _ = w.graphStore.GetEdgesForNode(r.Context(), id)
	}
	writeJSON(rw, http.StatusOK, map[string]any{
		"node":        node,
		"ancestors":   ancestors,
		"audit_trail": audit,
		"edges":       edges,
	})
}

func (w *WebServer) handleMemoryByID(rw http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/api/v1/memories/"))
	if id == "" || strings.Contains(id, "/") {
		http.Error(rw, "valid memory id required", http.StatusBadRequest)
		return
	}
	node, err := w.mgr.Store().GetByID(r.Context(), id)
	if err != nil || node == nil {
		http.Error(rw, "memory not found", http.StatusNotFound)
		return
	}
	switch r.Method {
	case http.MethodGet:
		var edges any
		if w.graphStore != nil {
			edges, _ = w.graphStore.GetEdgesForNode(r.Context(), id)
		}
		writeJSON(rw, http.StatusOK, map[string]any{"node": node, "edges": edges})
	case http.MethodDelete:
		// Security invariant: TIER_0_SOVEREIGN memories are immutable via the local Explorer UI.
		if node.AuthorityTier == authz.TierName0Sovereign {
			http.Error(rw, "Forbidden: TIER_0_SOVEREIGN memories cannot be deleted via Explorer UI (use supersession)", http.StatusForbidden)
			return
		}
		if err := w.mgr.Store().Delete(r.Context(), id); err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(rw, http.StatusOK, map[string]any{"id": id, "deleted": true})
	default:
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (w *WebServer) handleProposals(rw http.ResponseWriter, r *http.Request) {
	if w.expStore == nil {
		writeJSON(rw, http.StatusOK, map[string]any{"count": 0, "proposals": []any{}})
		return
	}
	nodes, err := w.expStore.ListProposals(r.Context(), 100)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	type propItem struct {
		ID              string    `json:"id"`
		SessionID       string    `json:"session_id"`
		Category        string    `json:"category"`
		Content         string    `json:"content"`
		AuthorityTier   string    `json:"authority_tier"`
		LifecycleStatus string    `json:"lifecycle_status"`
		CreatedAt       time.Time `json:"created_at"`
	}
	out := make([]propItem, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, propItem{
			ID:              n.ID,
			SessionID:       n.SessionID,
			Category:        n.Category,
			Content:         n.Content,
			AuthorityTier:   n.AuthorityTier,
			LifecycleStatus: n.LifecycleStatus,
			CreatedAt:       n.CreatedAt.UTC(),
		})
	}
	writeJSON(rw, http.StatusOK, map[string]any{"count": len(out), "proposals": out})
}

func (w *WebServer) handleObservations(rw http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	if status == "" {
		status = "open"
	}
	obs, err := w.mgr.ListObservations(r.Context(), "", "", status, "", 50)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(rw, http.StatusOK, map[string]any{"count": len(obs), "observations": obs})
}

func (w *WebServer) handleInbox(rw http.ResponseWriter, r *http.Request) {
	if w.inboxStore == nil {
		writeJSON(rw, http.StatusOK, map[string]any{"count": 0, "tickets": []any{}})
		return
	}
	tkts, err := w.inboxStore.ListPendingTickets(r.Context(), "", "pending", 50)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(rw, http.StatusOK, map[string]any{"count": len(tkts), "tickets": tkts})
}

func (w *WebServer) handleVerify(rw http.ResponseWriter, r *http.Request) {
	session := strings.TrimPrefix(r.URL.Path, "/api/v1/verify/")
	if session == "" {
		http.Error(rw, "session required", http.StatusBadRequest)
		return
	}
	ok, count, badID, err := w.mgr.VerifySessionChain(r.Context(), session)
	errStr := ""
	if err != nil {
		errStr = err.Error()
	}
	writeJSON(rw, http.StatusOK, map[string]any{
		"session": session, "verified": ok, "count": count, "bad_id": badID, "error": errStr,
	})
}

func (w *WebServer) handleObservationAction(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/resolve") {
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/observations/"), "/resolve")
	if err := w.mgr.ResolveObservation(r.Context(), id); err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(rw, http.StatusOK, map[string]any{"id": id, "status": "resolved"})
}

func (w *WebServer) handleProposalAction(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var id, newStatus, newTier string
	switch {
	case strings.HasSuffix(r.URL.Path, "/approve"):
		id = strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/proposals/"), "/approve")
		newStatus = string(authz.StatusActive)
		newTier = authz.TierName1Architecture
	case strings.HasSuffix(r.URL.Path, "/reject"):
		id = strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/proposals/"), "/reject")
		newStatus = string(authz.StatusRejected)
	default:
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	node, err := w.mgr.Store().GetByID(r.Context(), id)
	if err != nil || node == nil {
		http.Error(rw, "proposal not found", http.StatusNotFound)
		return
	}
	node.LifecycleStatus = newStatus
	if newTier != "" {
		node.AuthorityTier = newTier
	}
	node.UpdatedAt = time.Now()
	if err := w.mgr.Store().Store(r.Context(), node); err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(rw, http.StatusOK, map[string]any{"id": id, "lifecycle_status": node.LifecycleStatus, "authority_tier": node.AuthorityTier})
}

func (w *WebServer) handleIndex(rw http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(rw, r)
		return
	}
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = rw.Write([]byte(embeddedExplorerHTML))
}

const embeddedExplorerHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Coppermind — Local Memory Explorer</title>
<style>
  body { margin:0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; background:#0d1117; color:#e6edf3; }
  header { padding:10px 18px; border-bottom:1px solid #30363d; display:flex; align-items:center; justify-content:space-between; gap:10px; flex-wrap:wrap; }
  h1 { margin:0; font-size:15px; color:#f0883e; }
  .tabs { display:flex; gap:6px; flex-wrap:wrap; }
  .tab { background:#161b22; color:#c9d1d9; border:1px solid #30363d; border-radius:6px; padding:5px 10px; cursor:pointer; font-family:inherit; font-size:12px; }
  .tab.active { border-color:#f0883e; color:#f0883e; }
  .stats { font-size:11px; color:#8b949e; }
  main { display:grid; grid-template-columns: 400px 1fr 340px; height: calc(100vh - 54px); }
  aside { border-right:1px solid #30363d; padding:14px; overflow-y:auto; }
  #drawer { border-left:1px solid #30363d; padding:14px; overflow-y:auto; background:#0d1117; font-size:12px; }
  input { width:100%; box-sizing:border-box; padding:8px; background:#161b22; color:#e6edf3; border:1px solid #30363d; border-radius:6px; font-family:inherit; margin-bottom:6px; }
  .card { background:#161b22; border:1px solid #30363d; border-radius:6px; padding:10px; margin-top:10px; font-size:12px; cursor:pointer; }
  .card:hover { border-color:#58a6ff; }
  .badge { display:inline-block; padding:2px 6px; border-radius:4px; font-size:10px; background:#21262d; color:#f0883e; margin-right:5px; }
  .badge-muted { color:#8b949e; }
  .btn { background:#21262d; color:#e6edf3; border:1px solid #30363d; border-radius:4px; padding:4px 8px; cursor:pointer; font-family:inherit; font-size:11px; margin-top:6px; margin-right:6px; }
  .btn:hover { border-color:#f0883e; }
  .btn-danger { border-color:#f85149; color:#f85149; }
  .btn-danger:hover { background:#f8514922; }
  .canvas-wrap { position:relative; width:100%; height:100%; background:#090c10; }
  canvas { width:100%; height:100%; display:block; cursor:pointer; }
  .legend { position:absolute; bottom:10px; left:12px; font-size:10px; color:#8b949e; background:#0d1117cc; padding:4px 8px; border-radius:4px; border:1px solid #30363d; }
</style>
</head>
<body>
<header>
  <h1>🧠 Coppermind Memory Explorer</h1>
  <div class="tabs">
    <button class="tab active" data-tab="search">Search</button>
    <button class="tab" data-tab="timeline">Timeline</button>
    <button class="tab" data-tab="proposals">Proposals</button>
    <button class="tab" data-tab="obs">Observations</button>
    <button class="tab" data-tab="inbox">Inbox</button>
    <button class="tab" data-tab="verify">Merkle Verify</button>
  </div>
  <div class="stats" id="stats">Loading vault health...</div>
</header>
<main>
  <aside id="panel"></aside>
  <div class="canvas-wrap">
    <canvas id="graph"></canvas>
    <div class="legend">Click any node to inspect lineage &amp; edges · Color = repo/tier cluster</div>
  </div>
  <section id="drawer"><div style="color:#8b949e;">Select a memory or click a graph node to inspect its full content, edges, and supersession lineage.</div></section>
</main>
<script>
let csrfToken = '';
let allowCurate = false;
let graphPositions = [];
let selectedNodeId = '';
const statsEl = document.getElementById('stats');
const panelEl = document.getElementById('panel');
const drawerEl = document.getElementById('drawer');
const canvas = document.getElementById('graph');
const ctx = canvas.getContext('2d');
const palette = ['#58a6ff','#3fb950','#d29922','#bc8cff','#39c5cf','#f778ba','#ffa657'];

function escapeHtml(s) { return String(s||'').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function repoColor(n) {
  if (n.authority_tier === 'TIER_0_SOVEREIGN') return '#f85149';
  if (n.authority_tier === 'TIER_1_ARCHITECTURE') return '#f0883e';
  const repo = (n.metadata && n.metadata.git_repo) || n.session_id || '';
  let h = 0; for (let i = 0; i < repo.length; i++) h = (h * 31 + repo.charCodeAt(i)) >>> 0;
  return palette[h % palette.length];
}

async function loadHealth() {
  const r = await fetch('/api/v1/health');
  const d = await r.json();
  csrfToken = d.csrf_token || '';
  allowCurate = !!d.allow_curate;
  statsEl.textContent = 'Memories: ' + d.total_memories + ' | ' + d.active_model + ' | Obs: ' + d.open_high_obs + ' | Inbox: ' + d.pending_inbox + (allowCurate ? ' | Curate ON' : ' | Read-Only');
}

async function inspectNode(id) {
  if (!id) return;
  selectedNodeId = id;
  drawerEl.innerHTML = '<div style="color:#8b949e;">Loading lineage for ' + escapeHtml(id) + '...</div>';
  const r = await fetch('/api/v1/lineage/' + encodeURIComponent(id));
  if (!r.ok) { drawerEl.innerHTML = '<div class="card">Memory not found.</div>'; return; }
  const d = await r.json();
  const n = d.node || {};
  const repo = (n.metadata && n.metadata.git_repo) ? n.metadata.git_repo : '';
  let html = '<div style="font-weight:bold;color:#f0883e;margin-bottom:6px;">' + escapeHtml(n.id) + '</div>'
    + '<div><span class="badge">' + escapeHtml(n.authority_tier) + '</span><span class="badge badge-muted">' + escapeHtml(n.lifecycle_status || 'ACTIVE') + '</span><span class="badge badge-muted">' + escapeHtml(n.category) + '</span>' + (repo ? '<span class="badge badge-muted">' + escapeHtml(repo) + '</span>' : '') + '</div>'
    + '<div class="card" style="cursor:default;white-space:pre-wrap;word-break:break-word;">' + escapeHtml(n.content) + '</div>';

  if (allowCurate && n.authority_tier !== 'TIER_0_SOVEREIGN') {
    html += '<button class="btn btn-danger" id="delBtn">Delete Noisy Chunk</button>';
  } else if (n.authority_tier === 'TIER_0_SOVEREIGN') {
    html += '<div style="margin-top:6px;font-size:11px;color:#8b949e;">🔒 TIER_0_SOVEREIGN is immutable (delete disabled fail-closed).</div>';
  }

  const anc = d.ancestors || [];
  html += '<h3 style="font-size:12px;margin:14px 0 6px;color:#58a6ff;">Supersession Lineage (' + anc.length + ')</h3>';
  if (anc.length === 0) html += '<div style="color:#8b949e;">No ancestors.</div>';
  anc.forEach((a, idx) => {
    html += '<div class="card" data-inspect="' + escapeHtml(a.id) + '"><div>' + (idx === 0 ? '● ' : '↳ ') + '<span class="badge">' + escapeHtml(a.lifecycle_status || 'ACTIVE') + '</span>' + escapeHtml(a.id) + '</div>'
      + '<div style="margin-top:4px;color:#c9d1d9;">' + escapeHtml((a.content||'').slice(0, 120)) + '</div></div>';
  });

  const audit = d.audit_trail || [];
  if (audit.length > 0) {
    html += '<h3 style="font-size:12px;margin:14px 0 6px;color:#d29922;">Audit Rationale (' + audit.length + ')</h3>';
    audit.forEach(ev => {
      html += '<div class="card" style="cursor:default;">' + escapeHtml(ev.superseding_id) + ' → ' + escapeHtml(ev.superseded_id) + '<div style="margin-top:4px;color:#8b949e;">' + escapeHtml(ev.rationale) + '</div></div>';
    });
  }

  const edges = d.edges || [];
  html += '<h3 style="font-size:12px;margin:14px 0 6px;color:#3fb950;">Graph Edges (' + edges.length + ')</h3>';
  edges.slice(0, 20).forEach(e => {
    const dest = e.target_id || e.target_entity || '';
    html += '<div style="font-size:11px;padding:3px 0;border-bottom:1px solid #21262d;">' + escapeHtml(e.relation) + ' → <span style="color:#58a6ff;">' + escapeHtml(dest) + '</span></div>';
  });

  drawerEl.innerHTML = html;
  drawerEl.querySelectorAll('[data-inspect]').forEach(el => { el.onclick = () => { inspectNode(el.dataset.inspect); loadGraph(el.dataset.inspect); }; });
  const delBtn = document.getElementById('delBtn');
  if (delBtn) {
    delBtn.onclick = async () => {
      const resp = await fetch('/api/v1/memories/' + encodeURIComponent(n.id), { method:'DELETE', headers:{'X-Coppermind-CSRF': csrfToken} });
      if (resp.ok) {
        drawerEl.innerHTML = '<div class="card">✓ Deleted ' + escapeHtml(n.id) + '</div>';
        await loadHealth();
        loadGraph('');
      } else {
        drawerEl.innerHTML += '<div class="card" style="border-color:#f85149;">Delete blocked: ' + escapeHtml(await resp.text()) + '</div>';
      }
    };
  }
}

function showSearchTab() {
  panelEl.innerHTML = '<input id="q" placeholder="Hybrid + Graph recall (press Enter)..." /><input id="qSince" placeholder="Optional --since (e.g. 7d, 2026-11-20)" /><div id="results"></div>';
  const qEl = document.getElementById('q');
  const sEl = document.getElementById('qSince');
  const go = () => runSearch(qEl.value, sEl.value);
  qEl.addEventListener('keydown', e => { if (e.key === 'Enter') go(); });
  sEl.addEventListener('keydown', e => { if (e.key === 'Enter') go(); });
}

async function runSearch(query, since) {
  let url = '/api/v1/search?q=' + encodeURIComponent(query);
  if (since) url += '&since=' + encodeURIComponent(since);
  const r = await fetch(url);
  if (!r.ok) { document.getElementById('results').innerHTML = '<div class="card">' + escapeHtml(await r.text()) + '</div>'; return; }
  const d = await r.json();
  const resEl = document.getElementById('results');
  resEl.innerHTML = '';
  (d.results || []).forEach(item => {
    const div = document.createElement('div');
    div.className = 'card';
    const b = item.breakdown || {};
    div.innerHTML = '<div><span class="badge">' + escapeHtml(item.node.authority_tier) + '</span><span class="badge">' + (item.score||0).toFixed(3) + '</span></div>'
      + '<div style="margin-top:6px;white-space:pre-wrap;">' + escapeHtml((item.node.content||'').slice(0, 220)) + '</div>'
      + '<div style="margin-top:6px;color:#8b949e;font-size:11px;">hybrid=' + (b.hybrid_score||0).toFixed(2) + ' actr=' + (b.recency_actr||0).toFixed(2) + ' repo=' + (b.repo_affinity||0).toFixed(2) + '</div>';
    div.onclick = () => { loadGraph(item.node.id); inspectNode(item.node.id); };
    resEl.appendChild(div);
  });
}

async function showTimelineTab() {
  panelEl.innerHTML = '<input id="tlSince" placeholder="Filter --since (e.g. 7d, 24h)" /><input id="tlRepo" placeholder="Filter repo (e.g. coppermind)" /><button class="btn" id="tlGo">Refresh Timeline</button><div id="tlList"></div>';
  const load = async () => {
    let url = '/api/v1/timeline?limit=50';
    const s = document.getElementById('tlSince').value.trim();
    const repo = document.getElementById('tlRepo').value.trim();
    if (s) url += '&since=' + encodeURIComponent(s);
    if (repo) url += '&repo=' + encodeURIComponent(repo);
    const r = await fetch(url);
    const listEl = document.getElementById('tlList');
    if (!r.ok) { listEl.innerHTML = '<div class="card">' + escapeHtml(await r.text()) + '</div>'; return; }
    const d = await r.json();
    listEl.innerHTML = '<div style="font-size:11px;color:#8b949e;margin-top:6px;">Showing ' + (d.count||0) + ' chronological memories</div>';
    (d.items || []).forEach(it => {
      const div = document.createElement('div');
      div.className = 'card';
      div.innerHTML = '<div><span class="badge">' + escapeHtml(it.lifecycle_status || 'ACTIVE') + '</span><span class="badge badge-muted">' + escapeHtml(it.category) + '</span><span style="color:#8b949e;font-size:10px;">' + escapeHtml(String(it.created_at||'').slice(0,19).replace('T',' ')) + '</span></div>'
        + '<div style="margin-top:5px;">' + escapeHtml((it.content||'').slice(0, 180)) + '</div>';
      div.onclick = () => { inspectNode(it.id); loadGraph(it.id); };
      listEl.appendChild(div);
    });
  };
  document.getElementById('tlGo').onclick = load;
  load();
}

async function showProposalsTab() {
  const r = await fetch('/api/v1/proposals');
  const d = await r.json();
  panelEl.innerHTML = '<div style="font-size:12px;color:#8b949e;">PROPOSED Learnings &amp; Cartridge Imports (' + (d.count||0) + ')</div>';
  (d.proposals || []).forEach(p => {
    const div = document.createElement('div');
    div.className = 'card';
    div.innerHTML = '<div><span class="badge">' + escapeHtml(p.authority_tier) + '</span><span class="badge badge-muted">' + escapeHtml(p.category) + '</span></div>'
      + '<div style="margin-top:6px;">' + escapeHtml((p.content||'').slice(0, 220)) + '</div>';
    div.onclick = () => inspectNode(p.id);
    if (allowCurate) {
      const appBtn = document.createElement('button');
      appBtn.className = 'btn';
      appBtn.textContent = 'Approve → TIER_1';
      appBtn.onclick = async (e) => {
        e.stopPropagation();
        await fetch('/api/v1/proposals/' + encodeURIComponent(p.id) + '/approve', { method:'POST', headers:{'X-Coppermind-CSRF': csrfToken} });
        await loadHealth(); showProposalsTab();
      };
      const rejBtn = document.createElement('button');
      rejBtn.className = 'btn btn-danger';
      rejBtn.textContent = 'Reject';
      rejBtn.onclick = async (e) => {
        e.stopPropagation();
        await fetch('/api/v1/proposals/' + encodeURIComponent(p.id) + '/reject', { method:'POST', headers:{'X-Coppermind-CSRF': csrfToken} });
        await loadHealth(); showProposalsTab();
      };
      div.appendChild(appBtn);
      div.appendChild(rejBtn);
    }
    panelEl.appendChild(div);
  });
}

async function showObsTab() {
  const r = await fetch('/api/v1/observations?status=open');
  const d = await r.json();
  panelEl.innerHTML = '<div style="font-size:12px;color:#8b949e;">Open Observations (' + (d.count||0) + ')</div>';
  (d.observations || []).forEach(o => {
    const div = document.createElement('div');
    div.className = 'card';
    div.innerHTML = '<div><span class="badge">' + escapeHtml(o.severity) + '</span><span class="badge">' + escapeHtml(o.source_lens) + '</span></div>'
      + '<div style="margin-top:6px;">' + escapeHtml((o.content||'').slice(0, 220)) + '</div>';
    if (allowCurate) {
      const btn = document.createElement('button');
      btn.className = 'btn';
      btn.textContent = 'Resolve';
      btn.onclick = async (e) => {
        e.stopPropagation();
        await fetch('/api/v1/observations/' + encodeURIComponent(o.id) + '/resolve', { method:'POST', headers:{'X-Coppermind-CSRF': csrfToken} });
        await loadHealth(); showObsTab();
      };
      div.appendChild(btn);
    }
    panelEl.appendChild(div);
  });
}

async function showInboxTab() {
  const r = await fetch('/api/v1/inbox');
  const d = await r.json();
  panelEl.innerHTML = '<div style="font-size:12px;color:#8b949e;">Pending Zero-Key Commit Lens Inbox (' + (d.count||0) + ')</div>';
  (d.tickets || []).forEach(t => {
    const div = document.createElement('div');
    div.className = 'card';
    div.innerHTML = '<div><span class="badge">' + escapeHtml(t.lens_name) + '</span><span class="badge">' + escapeHtml(t.branch_name) + '</span></div>'
      + '<div style="margin-top:6px;">' + escapeHtml(t.summary) + '</div>';
    div.onclick = () => inspectNode(t.memory_id);
    panelEl.appendChild(div);
  });
}

function showVerifyTab() {
  panelEl.innerHTML = '<input id="sess" value="default" placeholder="Session ID to Merkle-verify..." /><button class="btn" id="vbtn">Verify Session Chain</button><div id="vout"></div>';
  document.getElementById('vbtn').onclick = async () => {
    const s = document.getElementById('sess').value || 'default';
    const r = await fetch('/api/v1/verify/' + encodeURIComponent(s));
    const d = await r.json();
    document.getElementById('vout').innerHTML = '<div class="card">' + (d.verified ? '✓ INTACT (' + d.count + ' nodes)' : '✗ FAILED: ' + escapeHtml(d.error)) + '</div>';
  };
}

async function loadGraph(center) {
  const r = await fetch('/api/v1/graph' + (center ? '?center=' + encodeURIComponent(center) : ''));
  const d = await r.json();
  canvas.width = canvas.clientWidth; canvas.height = canvas.clientHeight;
  const nodes = d.nodes || [];
  const edges = d.edges || [];
  const cx = canvas.width / 2, cy = canvas.height / 2, rad = Math.min(cx, cy) * 0.68;
  const posMap = {};
  const pts = nodes.map((n, i) => {
    const a = (i / Math.max(nodes.length, 1)) * Math.PI * 2;
    const p = { x: cx + Math.cos(a) * rad * (0.65 + (i % 3) * 0.16), y: cy + Math.sin(a) * rad * (0.65 + (i % 3) * 0.16), vx: 0, vy: 0, n };
    posMap[n.id] = p;
    return p;
  });

  // Lightweight deterministic force-directed relaxation (45 ticks, zero external libs)
  for (let iter = 0; iter < 45; iter++) {
    for (let i = 0; i < pts.length; i++) {
      for (let j = i + 1; j < pts.length; j++) {
        const dx = pts[j].x - pts[i].x, dy = pts[j].y - pts[i].y;
        const dist2 = dx * dx + dy * dy + 25;
        const f = 900 / dist2;
        const dist = Math.sqrt(dist2);
        pts[i].vx -= (dx / dist) * f; pts[i].vy -= (dy / dist) * f;
        pts[j].vx += (dx / dist) * f; pts[j].vy += (dy / dist) * f;
      }
    }
    edges.forEach(e => {
      const s = posMap[e.source_id], t = posMap[e.target_id];
      if (!s || !t) return;
      const dx = t.x - s.x, dy = t.y - s.y;
      s.vx += dx * 0.015; s.vy += dy * 0.015;
      t.vx -= dx * 0.015; t.vy -= dy * 0.015;
    });
    pts.forEach(p => {
      p.vx = (p.vx + (cx - p.x) * 0.008) * 0.78;
      p.vy = (p.vy + (cy - p.y) * 0.008) * 0.78;
      p.x = Math.max(24, Math.min(canvas.width - 24, p.x + p.vx));
      p.y = Math.max(24, Math.min(canvas.height - 24, p.y + p.vy));
    });
  }
  graphPositions = pts;

  ctx.clearRect(0, 0, canvas.width, canvas.height);
  ctx.strokeStyle = '#30363d';
  edges.forEach(e => {
    const s = posMap[e.source_id], t = posMap[e.target_id];
    if (s && t) { ctx.beginPath(); ctx.moveTo(s.x, s.y); ctx.lineTo(t.x, t.y); ctx.stroke(); }
  });
  pts.forEach(p => {
    const isSel = p.n.id === selectedNodeId;
    ctx.fillStyle = repoColor(p.n);
    ctx.beginPath(); ctx.arc(p.x, p.y, isSel ? 9 : 6, 0, Math.PI * 2); ctx.fill();
    if (isSel) { ctx.strokeStyle = '#ffffff'; ctx.lineWidth = 2; ctx.stroke(); ctx.lineWidth = 1; }
    ctx.fillStyle = '#c9d1d9'; ctx.font = '10px monospace';
    ctx.fillText((p.n.category || p.n.id).slice(0, 18), p.x + 9, p.y + 3);
  });
}

canvas.addEventListener('click', ev => {
  const rect = canvas.getBoundingClientRect();
  const mx = ev.clientX - rect.left, my = ev.clientY - rect.top;
  let hit = null, best = 18;
  graphPositions.forEach(p => {
    const dist = Math.hypot(p.x - mx, p.y - my);
    if (dist < best) { best = dist; hit = p; }
  });
  if (hit) { inspectNode(hit.n.id); loadGraph(hit.n.id); }
});

document.querySelectorAll('.tab').forEach(btn => {
  btn.onclick = () => {
    document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    const t = btn.dataset.tab;
    if (t === 'search') showSearchTab();
    else if (t === 'timeline') showTimelineTab();
    else if (t === 'proposals') showProposalsTab();
    else if (t === 'obs') showObsTab();
    else if (t === 'inbox') showInboxTab();
    else if (t === 'verify') showVerifyTab();
  };
});

loadHealth();
showSearchTab();
loadGraph('');
</script>
</body>
</html>`
