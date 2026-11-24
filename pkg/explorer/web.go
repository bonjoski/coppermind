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
	"github.com/bonjoski/coppermind/pkg/storage/sqlite"
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
	store       *sqlite.SQLiteStore
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

	sqlStore, _ := mgr.Store().(*sqlite.SQLiteStore)
	ws := &WebServer{
		mgr:       mgr,
		store:     sqlStore,
		opts:      opts,
		token:     hex.EncodeToString(tokBytes),
		csrfToken: hex.EncodeToString(csrfBytes),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", ws.handleIndex)
	mux.HandleFunc("/api/v1/health", ws.handleHealth)
	mux.HandleFunc("/api/v1/search", ws.handleSearch)
	mux.HandleFunc("/api/v1/graph", ws.handleGraph)
	mux.HandleFunc("/api/v1/observations", ws.handleObservations)
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
	var cov *sqlite.VectorCoverage
	if w.store != nil {
		if tkts, err := w.store.ListPendingTickets(r.Context(), "", "pending", 100); err == nil {
			pendingCount = len(tkts)
		}
		cov, _ = w.store.GetVectorCoverage(r.Context(), w.mgr.EmbedderModelName())
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
		t, err := brain.ParseTemporalBound(since, time.Now().UTC())
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}
		req.CreatedAfter = &t
	}
	res, err := w.mgr.Recall(r.Context(), req)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(rw, http.StatusOK, map[string]any{"count": len(res), "results": res})
}

func (w *WebServer) handleGraph(rw http.ResponseWriter, r *http.Request) {
	if w.store == nil {
		writeJSON(rw, http.StatusOK, map[string]any{"nodes": []any{}, "edges": []any{}})
		return
	}
	center := strings.TrimSpace(r.URL.Query().Get("center"))
	nodes, edges, err := w.store.GetGraphSubgraph(r.Context(), center, 100, 250)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(rw, http.StatusOK, map[string]any{"nodes": nodes, "edges": edges})
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
	if w.store == nil {
		writeJSON(rw, http.StatusOK, map[string]any{"count": 0, "tickets": []any{}})
		return
	}
	tkts, err := w.store.ListPendingTickets(r.Context(), "", "pending", 50)
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
	if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/approve") {
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/proposals/"), "/approve")
	node, err := w.mgr.Store().GetByID(r.Context(), id)
	if err != nil || node == nil {
		http.Error(rw, "proposal not found", http.StatusNotFound)
		return
	}
	node.LifecycleStatus = string(authz.StatusActive)
	node.AuthorityTier = authz.TierName1Architecture
	node.UpdatedAt = time.Now()
	if err := w.mgr.Store().Store(r.Context(), node); err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(rw, http.StatusOK, map[string]any{"id": id, "lifecycle_status": "ACTIVE", "authority_tier": node.AuthorityTier})
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
<title>Coppermind — Local Brain Explorer</title>
<style>
  body { margin:0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; background:#0d1117; color:#e6edf3; }
  header { padding:12px 20px; border-bottom:1px solid #30363d; display:flex; align-items:center; justify-content:space-between; gap:12px; }
  h1 { margin:0; font-size:15px; color:#f0883e; }
  .tabs { display:flex; gap:6px; }
  .tab { background:#161b22; color:#c9d1d9; border:1px solid #30363d; border-radius:6px; padding:5px 10px; cursor:pointer; font-family:inherit; font-size:12px; }
  .tab.active { border-color:#f0883e; color:#f0883e; }
  .stats { font-size:11px; color:#8b949e; }
  main { display:grid; grid-template-columns: 400px 1fr; height: calc(100vh - 54px); }
  aside { border-right:1px solid #30363d; padding:14px; overflow-y:auto; }
  input { width:100%; box-sizing:border-box; padding:8px; background:#161b22; color:#e6edf3; border:1px solid #30363d; border-radius:6px; font-family:inherit; }
  .card { background:#161b22; border:1px solid #30363d; border-radius:6px; padding:10px; margin-top:10px; font-size:12px; }
  .badge { display:inline-block; padding:2px 6px; border-radius:4px; font-size:10px; background:#21262d; color:#f0883e; margin-right:6px; }
  .btn { background:#21262d; color:#e6edf3; border:1px solid #30363d; border-radius:4px; padding:4px 8px; cursor:pointer; font-family:inherit; font-size:11px; margin-top:6px; margin-right:6px; }
  .btn:hover { border-color:#f0883e; }
  canvas { width:100%; height:100%; display:block; background:#090c10; }
</style>
</head>
<body>
<header>
  <h1>🧠 Coppermind Brain Explorer</h1>
  <div class="tabs">
    <button class="tab active" data-tab="search">Search</button>
    <button class="tab" data-tab="obs">Observations</button>
    <button class="tab" data-tab="inbox">Inbox</button>
    <button class="tab" data-tab="verify">Merkle Verify</button>
  </div>
  <div class="stats" id="stats">Loading vault health...</div>
</header>
<main>
  <aside id="panel"></aside>
  <canvas id="graph"></canvas>
</main>
<script>
let csrfToken = '';
let allowCurate = false;
const statsEl = document.getElementById('stats');
const panelEl = document.getElementById('panel');
const canvas = document.getElementById('graph');
const ctx = canvas.getContext('2d');

function escapeHtml(s) { return String(s||'').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

async function loadHealth() {
  const r = await fetch('/api/v1/health');
  const d = await r.json();
  csrfToken = d.csrf_token || '';
  allowCurate = !!d.allow_curate;
  statsEl.textContent = 'Memories: ' + d.total_memories + ' | ' + d.active_model + ' | Obs: ' + d.open_high_obs + ' | Inbox: ' + d.pending_inbox + (allowCurate ? ' | Curate ON' : ' | Read-Only');
}

function showSearchTab() {
  panelEl.innerHTML = '<input id="q" placeholder="Hybrid + Graph recall (press Enter)..." /><div id="results"></div>';
  const qEl = document.getElementById('q');
  qEl.addEventListener('keydown', e => { if (e.key === 'Enter') runSearch(qEl.value); });
}

async function runSearch(query) {
  const r = await fetch('/api/v1/search?q=' + encodeURIComponent(query));
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
    div.onclick = () => loadGraph(item.node.id);
    resEl.appendChild(div);
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
      btn.onclick = async () => {
        await fetch('/api/v1/observations/' + encodeURIComponent(o.id) + '/resolve', { method:'POST', headers:{'X-Coppermind-CSRF': csrfToken} });
        await loadHealth();
        showObsTab();
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
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  const nodes = d.nodes || [];
  const cx = canvas.width / 2, cy = canvas.height / 2, rad = Math.min(cx, cy) * 0.72;
  const pos = {};
  nodes.forEach((n, i) => {
    const a = (i / Math.max(nodes.length, 1)) * Math.PI * 2;
    pos[n.id] = { x: cx + Math.cos(a) * rad, y: cy + Math.sin(a) * rad, n };
  });
  ctx.strokeStyle = '#30363d';
  (d.edges || []).forEach(e => {
    const s = pos[e.source_id], t = pos[e.target_id];
    if (s && t) { ctx.beginPath(); ctx.moveTo(s.x, s.y); ctx.lineTo(t.x, t.y); ctx.stroke(); }
  });
  Object.values(pos).forEach(p => {
    ctx.fillStyle = p.n.authority_tier === 'TIER_0_SOVEREIGN' ? '#f85149' : (p.n.authority_tier === 'TIER_1_ARCHITECTURE' ? '#f0883e' : '#58a6ff');
    ctx.beginPath(); ctx.arc(p.x, p.y, 6, 0, Math.PI * 2); ctx.fill();
    ctx.fillStyle = '#c9d1d9'; ctx.font = '10px monospace';
    ctx.fillText((p.n.category || p.n.id).slice(0, 18), p.x + 9, p.y + 3);
  });
}

document.querySelectorAll('.tab').forEach(btn => {
  btn.onclick = () => {
    document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    const t = btn.dataset.tab;
    if (t === 'search') showSearchTab();
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
