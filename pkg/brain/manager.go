package brain

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/bonjoski/coppermind/pkg/authz"
	"github.com/bonjoski/coppermind/pkg/gitscope"
	"github.com/bonjoski/coppermind/pkg/scope"
	"golang.org/x/text/unicode/norm"
)

// RememberRequest specifies input parameters for storing a memory.
type RememberRequest struct {
	SessionID   string            `json:"session_id"`
	Category    string            `json:"category"`
	Content     string            `json:"content"`
	Provenance  ProvenanceTier    `json:"provenance"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	TTL         time.Duration     `json:"ttl,omitempty"`
	Deduplicate bool              `json:"deduplicate,omitempty"`

	// Cognitive Lenses fields
	Derived    bool     `json:"derived,omitempty"`
	SourceLens string   `json:"source_lens,omitempty"`
	ParentIDs  []string `json:"parent_ids,omitempty"`
	Severity   string   `json:"severity,omitempty"`
	Status     string   `json:"status,omitempty"`
	DedupHash  string   `json:"dedup_hash,omitempty"`

	// Epistemic Authority & Supersession fields (RFC-2026-11-15-33)
	AuthorityTier   string `json:"authority_tier,omitempty"`
	LifecycleStatus string `json:"lifecycle_status,omitempty"`
	AuthorIdentity  string `json:"author_identity,omitempty"`
	AuthorRole      string `json:"author_role,omitempty"`
	SupersedesID    string `json:"supersedes_id,omitempty"`
	Rationale       string `json:"rationale,omitempty"`
	AdvisoryRef     string `json:"advisory_ref,omitempty"`

	// Hierarchical Scope field (RFC-2026-11-24-58): "" = vault-global
	Scope string `json:"scope,omitempty"`
}

// RecallRequest specifies query parameters for retrieving memories.
type RecallRequest struct {
	SessionID           string         `json:"session_id,omitempty"`
	Category            string         `json:"category,omitempty"`
	Query               string         `json:"query"`
	Limit               int            `json:"limit,omitempty"`
	MinScore            float32        `json:"min_score,omitempty"`
	Provenance          ProvenanceTier `json:"provenance,omitempty"`
	Hybrid              bool           `json:"hybrid,omitempty"`
	GitRepo             string         `json:"git_repo,omitempty"`
	GitBranch           string         `json:"git_branch,omitempty"`
	Derived             *bool          `json:"derived,omitempty"`
	SourceLens          string         `json:"source_lens,omitempty"`
	Severity            string         `json:"severity,omitempty"`
	Status              string         `json:"status,omitempty"`
	IncludeObservations bool           `json:"include_observations,omitempty"`

	// Epistemic Authority & Lifecycle filters
	AuthorityTier     string `json:"authority_tier,omitempty"`
	LifecycleStatus   string `json:"lifecycle_status,omitempty"`
	IncludeSuperseded bool   `json:"include_superseded,omitempty"`

	// Temporal, Graph & Reranking filters (RFC-2026-11-24-55 / RFC-2026-11-24-56)
	CreatedAfter  *time.Time `json:"created_after,omitempty"`
	CreatedBefore *time.Time `json:"created_before,omitempty"`
	Hops          int        `json:"hops,omitempty"`
	ActiveRepo    string     `json:"active_repo,omitempty"`
	ActiveBranch  string     `json:"active_branch,omitempty"`
	DisableMMR    bool       `json:"disable_mmr,omitempty"`
	Explain       bool       `json:"explain,omitempty"`

	// Hierarchical Scope filters (RFC-2026-11-24-58)
	Scope       string     `json:"scope,omitempty"`
	ScopeMode   scope.Mode `json:"scope_mode,omitempty"`
	ActiveScope string     `json:"active_scope,omitempty"`
}

// EventHook is invoked when a canonical memory is successfully stored.
type EventHook func(ctx context.Context, topic string, node *MemoryNode)

type accessEvent struct {
	sessionID string
	nodeID    string
}

type accessBatchStore interface {
	IncrementAccessBatch(ctx context.Context, ids []string, accessedAt time.Time) error
}

type namedEmbedder interface {
	ModelName() string
}

// Manager orchestrates the cognitive memory store, embedder, and scratchpad.
type Manager struct {
	store      MemoryStore
	embedder   Embedder
	scratchpad Scratchpad
	validator  *MemoryValidator
	eventHook  EventHook

	accessCh   chan accessEvent
	accessStop chan struct{}
	accessWg   sync.WaitGroup
	closeOnce  sync.Once
}

// NewManager creates a new brain manager with an embedded Stormcage-backed MemoryValidator,
// auto-wiring the pre-write integrity hook on compatible stores (e.g. SQLiteStore WAL pipeline)
// and wrapping the working-memory Scratchpad for fail-closed prompt injection defense.
func NewManager(store MemoryStore, embedder Embedder, scratchpad Scratchpad) *Manager {
	validator := NewMemoryValidator()

	type preWriteHookable interface {
		SetPreWriteHook(fn func(ctx context.Context, node *MemoryNode) error)
	}
	if hookable, ok := store.(preWriteHookable); ok {
		hookable.SetPreWriteHook(validator.ValidateNodeForStorage)
	}

	var wrappedScratchpad Scratchpad
	if scratchpad != nil {
		wrappedScratchpad = NewValidatedScratchpad(scratchpad, validator, "default", ProvenanceSharedDoc)
	}

	mgr := &Manager{
		store:      store,
		embedder:   embedder,
		scratchpad: wrappedScratchpad,
		validator:  validator,
		accessCh:   make(chan accessEvent, 256),
		accessStop: make(chan struct{}),
	}

	if _, ok := store.(accessBatchStore); ok {
		mgr.accessWg.Add(1)
		go mgr.runAccessCoalescer()
	}

	return mgr
}

// Embedder returns the configured vector embedder.
func (m *Manager) Embedder() Embedder {
	return m.embedder
}

// EmbedderModelName returns the canonical model name of the active embedder.
func (m *Manager) EmbedderModelName() string {
	if m.embedder == nil {
		return "unknown"
	}
	if named, ok := m.embedder.(namedEmbedder); ok && strings.TrimSpace(named.ModelName()) != "" {
		return named.ModelName()
	}
	return fmt.Sprintf("local-hash-%d", m.embedder.Dimension())
}

func (m *Manager) runAccessCoalescer() {
	defer m.accessWg.Done()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	cooldown := make(map[string]time.Time)
	pending := make(map[string]struct{})
	const cooldownWindow = 10 * time.Minute

	flush := func() {
		if len(pending) == 0 {
			return
		}
		batchStore, ok := m.store.(accessBatchStore)
		if !ok {
			clear(pending)
			return
		}
		ids := make([]string, 0, len(pending))
		for id := range pending {
			ids = append(ids, id)
		}
		clear(pending)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = batchStore.IncrementAccessBatch(ctx, ids, time.Now())
		cancel()
	}

	for {
		select {
		case ev := <-m.accessCh:
			now := time.Now()
			key := ev.sessionID + ":" + ev.nodeID
			if last, ok := cooldown[key]; ok && now.Sub(last) < cooldownWindow {
				continue
			}
			cooldown[key] = now
			pending[ev.nodeID] = struct{}{}
			if len(cooldown) > 4096 {
				for k, ts := range cooldown {
					if now.Sub(ts) >= cooldownWindow {
						delete(cooldown, k)
					}
				}
			}
		case <-ticker.C:
			flush()
		case <-m.accessStop:
			flush()
			return
		}
	}
}

func (m *Manager) recordAccessAsync(sessionID string, results []*SearchResult) {
	if m.accessCh == nil {
		return
	}
	if sessionID == "" {
		sessionID = "default"
	}
	for _, r := range results {
		if r == nil || r.Node == nil {
			continue
		}
		// Security invariant: TAINT_* memories never accumulate ACT-R access reinforcement.
		if r.Node.Provenance != ProvenanceLocalWorkspace {
			continue
		}
		select {
		case m.accessCh <- accessEvent{sessionID: sessionID, nodeID: r.Node.ID}:
		default:
			// Drop-if-full: zero backpressure on read path.
		}
	}
}

// Validator returns the embedded Stormcage-backed MemoryValidator for direct diff or scratchpad audits.
func (m *Manager) Validator() *MemoryValidator {
	if m.validator == nil {
		m.validator = NewMemoryValidator()
	}
	return m.validator
}

// SetEventHook registers an event listener for memory lifecycle events.
func (m *Manager) SetEventHook(hook EventHook) {
	m.eventHook = hook
}

// Store returns the underlying memory store.
func (m *Manager) Store() MemoryStore {
	return m.store
}

// Remember sanitizes, embeds, and stores a new memory node.
// Enforces strict secret quarantine: credentials and private keys are never stored.
func (m *Manager) Remember(ctx context.Context, req RememberRequest) (*MemoryNode, error) {
	if strings.TrimSpace(req.Content) == "" {
		return nil, fmt.Errorf("content cannot be empty")
	}

	normScope, err := scope.Normalize(req.Scope)
	if err != nil {
		return nil, err
	}

	if req.Provenance == "" {
		req.Provenance = ProvenanceLocalWorkspace
	}
	if req.SessionID == "" {
		req.SessionID = "default"
	}

	// 1. Memory and Scratchpad Integrity Validation (Author attribution, delimiter defanging, cognitive threat, and quarantine partition)
	if m.validator == nil {
		m.validator = NewMemoryValidator()
	}
	verdict, err := m.validator.Validate(ctx, &req)
	if err != nil {
		return nil, err
	}

	// 2. Normalize content via NFKC and strip invisible runes
	normalized := sanitizeText(verdict.CleanedContent)

	if req.Category == "" {
		req.Category = "general"
	}

	metadata := req.Metadata
	if verdict.RedactedCount > 0 {
		if metadata == nil {
			metadata = make(map[string]string)
		}
		metadata["redacted_secrets"] = fmt.Sprintf("%d", verdict.RedactedCount)
	}
	if len(verdict.Flags) > 0 {
		if metadata == nil {
			metadata = make(map[string]string)
		}
		metadata["firewall_flags"] = strings.Join(verdict.Flags, ",")
	}

	// Automatic ambient Git repository & branch detection
	if req.Provenance == ProvenanceLocalWorkspace {
		gitCtx := gitscope.Detect("")
		if gitCtx.IsGit {
			if metadata == nil {
				metadata = make(map[string]string)
			}
			if _, exists := metadata["git_repo"]; !exists && gitCtx.RepoName != "" {
				metadata["git_repo"] = gitCtx.RepoName
			}
			if _, exists := metadata["git_branch"]; !exists && gitCtx.Branch != "" {
				metadata["git_branch"] = gitCtx.Branch
			}
			if _, exists := metadata["git_commit"]; !exists && gitCtx.Commit != "" {
				metadata["git_commit"] = gitCtx.Commit
			}
		}
	}

	// 4. Generate embedding vector from sanitized content
	vec, err := m.embedder.Embed(ctx, normalized)
	if err != nil {
		return nil, fmt.Errorf("embedding generation failed: %w", err)
	}

	// 5. Intelligent Near-Duplicate Deduplication: Check if identical content exists in session+scope if requested
	if req.Deduplicate {
		existing, _ := m.store.RecallSemantic(ctx, vec, MemoryFilter{
			SessionID: req.SessionID,
			Category:  req.Category,
			Scope:     normScope,
			ScopeMode: scope.ModeExact,
			Limit:     1,
			MinScore:  0.98,
		})
		if len(existing) > 0 && strings.EqualFold(existing[0].Node.Content, normalized) {
			existingNode := existing[0].Node
			existingNode.UpdatedAt = time.Now()
			if metadata != nil {
				if existingNode.Metadata == nil {
					existingNode.Metadata = make(map[string]string)
				}
				for k, v := range metadata {
					existingNode.Metadata[k] = v
				}
			}
			_ = m.store.Store(ctx, existingNode)
			return existingNode, nil
		}
	}

	id := generateID()
	now := time.Now()

	var expiresAt *time.Time
	if req.TTL > 0 {
		exp := now.Add(req.TTL)
		expiresAt = &exp
	}

	status := req.Status
	if req.Derived && status == "" {
		status = "open"
	}

	tier := req.AuthorityTier
	if tier == "" {
		tier = authz.TierToString(authz.CategoryToDefaultTier(req.Category))
	}
	lifecycleStatus := req.LifecycleStatus
	if lifecycleStatus == "" {
		lifecycleStatus = string(authz.StatusActive)
	}

	contentSum := sha256.Sum256([]byte(normalized))
	node := &MemoryNode{
		ID:              id,
		SessionID:       req.SessionID,
		Category:        req.Category,
		Content:         normalized,
		Vector:          vec,
		Provenance:      req.Provenance,
		TaintScore:      verdict.TaintScore,
		Metadata:        metadata,
		CreatedAt:       now,
		UpdatedAt:       now,
		ExpiresAt:       expiresAt,
		Derived:         req.Derived,
		SourceLens:      req.SourceLens,
		ParentIDs:       req.ParentIDs,
		Severity:        req.Severity,
		Status:          status,
		DedupHash:       req.DedupHash,
		AuthorityTier:   tier,
		LifecycleStatus: lifecycleStatus,
		AuthorIdentity:  req.AuthorIdentity,
		AuthorRole:      req.AuthorRole,
		SupersedesID:    req.SupersedesID,
		Rationale:       req.Rationale,
		AdvisoryRef:     req.AdvisoryRef,
		EmbeddingModel:  m.EmbedderModelName(),
		EmbeddingDim:    len(vec),
		ContentSHA256:   hex.EncodeToString(contentSum[:]),
		Scope:           normScope,
	}

	type superseder interface {
		Supersede(ctx context.Context, supersedingNode *MemoryNode, targetID string, rationale, advisoryRef string, authorIdentity, authorRole string) error
	}

	if req.SupersedesID != "" {
		// Fail-closed cross-scope supersession guard (also enforced atomically inside storage tx).
		if target, tErr := m.store.GetByID(ctx, req.SupersedesID); tErr == nil && target != nil {
			if target.Scope != normScope {
				return nil, fmt.Errorf("%w: cannot supersede memory %q in scope %q from scope %q",
					scope.ErrCrossScopeSupersession, req.SupersedesID, target.Scope, normScope)
			}
		}
		if s, ok := m.store.(superseder); ok {
			if err := s.Supersede(ctx, node, req.SupersedesID, req.Rationale, req.AdvisoryRef, req.AuthorIdentity, req.AuthorRole); err != nil {
				return nil, fmt.Errorf("supersession failed: %w", err)
			}
		} else {
			if err := m.store.Store(ctx, node); err != nil {
				return nil, fmt.Errorf("failed to persist memory node: %w", err)
			}
			if target, err := m.store.GetByID(ctx, req.SupersedesID); err == nil && target != nil {
				target.LifecycleStatus = string(authz.StatusSuperseded)
				target.SupersededByID = node.ID
				target.UpdatedAt = time.Now()
				_ = m.store.Store(ctx, target)
			}
		}
	} else {
		if err := m.store.Store(ctx, node); err != nil {
			return nil, fmt.Errorf("failed to persist memory node: %w", err)
		}
	}

	// Loop Prevention Invariant: Records with derived=true MUST NOT emit ingest.* or episodic.* events
	if !node.Derived && m.eventHook != nil {
		m.eventHook(ctx, fmt.Sprintf("ingest.%s", node.Category), node)
		if node.Category == "commit" || node.Category == "git_commit" || (metadata != nil && metadata["git_commit"] != "") {
			m.eventHook(ctx, "episodic.commit", node)
		}
	}

	return node, nil
}

// Recall performs semantic or hybrid similarity search over stored memory nodes.
func (m *Manager) Recall(ctx context.Context, req RecallRequest) ([]*SearchResult, error) {
	if strings.TrimSpace(req.Query) == "" {
		return nil, fmt.Errorf("query cannot be empty")
	}

	normScope, err := scope.Normalize(req.Scope)
	if err != nil {
		return nil, err
	}
	normActiveScope, err := scope.Normalize(req.ActiveScope)
	if err != nil {
		return nil, err
	}
	scopeMode := req.ScopeMode
	if scopeMode != "" {
		scopeMode, err = scope.ParseMode(string(scopeMode))
		if err != nil {
			return nil, err
		}
	} else if normScope != "" {
		scopeMode = scope.ModeAncestors
	}

	normalizedQuery := sanitizeText(req.Query)
	queryVec, err := m.embedder.Embed(ctx, normalizedQuery)
	if err != nil {
		return nil, fmt.Errorf("embedding generation failed: %w", err)
	}

	targetLimit := req.Limit
	if targetLimit <= 0 {
		targetLimit = 10
	}
	candidateLimit := targetLimit * 4
	if candidateLimit < 24 {
		candidateLimit = 24
	}

	filter := MemoryFilter{
		SessionID:           req.SessionID,
		Category:            req.Category,
		Provenance:          req.Provenance,
		MinScore:            0, // Apply MinScore after composite normalization
		Limit:               candidateLimit,
		Hybrid:              req.Hybrid,
		GitRepo:             req.GitRepo,
		GitBranch:           req.GitBranch,
		Derived:             req.Derived,
		SourceLens:          req.SourceLens,
		Severity:            req.Severity,
		Status:              req.Status,
		IncludeObservations: req.IncludeObservations,
		AuthorityTier:       req.AuthorityTier,
		LifecycleStatus:     req.LifecycleStatus,
		IncludeSuperseded:   req.IncludeSuperseded,
		CreatedAfter:        req.CreatedAfter,
		CreatedBefore:       req.CreatedBefore,
		Hops:                req.Hops,
		ActiveRepo:          req.ActiveRepo,
		ActiveBranch:        req.ActiveBranch,
		DisableMMR:          req.DisableMMR,
		Explain:             req.Explain,
		Scope:               normScope,
		ScopeMode:           scopeMode,
		ActiveScope:         normActiveScope,
	}

	var results []*SearchResult
	if req.Hybrid {
		results, err = m.store.RecallHybrid(ctx, normalizedQuery, queryVec, filter)
	} else {
		results, err = m.store.RecallSemantic(ctx, queryVec, filter)
	}
	if err != nil {
		return nil, err
	}

	// Optional bounded 1-2 hop Knowledge Graph expansion (RFC-2026-11-24-55)
	type graphExpander interface {
		ExpandGraphNeighbors(ctx context.Context, seedIDs []string, maxHops int, filter MemoryFilter) ([]*SearchResult, error)
	}
	if req.Hops > 0 && len(results) > 0 {
		if expander, ok := m.store.(graphExpander); ok {
			seedCount := len(results)
			if seedCount > 5 {
				seedCount = 5
			}
			seedIDs := make([]string, 0, seedCount)
			seen := make(map[string]*SearchResult, len(results))
			for i, r := range results {
				if r != nil && r.Node != nil {
					seen[r.Node.ID] = r
					if i < seedCount {
						seedIDs = append(seedIDs, r.Node.ID)
					}
				}
			}
			if neighbors, gErr := expander.ExpandGraphNeighbors(ctx, seedIDs, req.Hops, filter); gErr == nil {
				for _, n := range neighbors {
					if n == nil || n.Node == nil {
						continue
					}
					if existing, exists := seen[n.Node.ID]; exists {
						existing.GraphLinks = append(existing.GraphLinks, n.GraphLinks...)
					} else {
						seen[n.Node.ID] = n
						results = append(results, n)
					}
				}
			}
		}
	}

	activeRepo := req.ActiveRepo
	activeBranch := req.ActiveBranch
	if activeRepo == "" && req.GitRepo != "" {
		activeRepo = req.GitRepo
		activeBranch = req.GitBranch
	}

	activeScope := normActiveScope
	if activeScope == "" && normScope != "" {
		activeScope = normScope
	}

	rerankCfg := DefaultRerankConfig()
	rerankCfg.ActiveRepo = activeRepo
	rerankCfg.ActiveBranch = activeBranch
	rerankCfg.ActiveScope = activeScope
	rerankCfg.DisableMMR = req.DisableMMR
	rerankCfg.Limit = targetLimit

	results = RerankResults(results, rerankCfg)

	if req.MinScore > 0 {
		filtered := make([]*SearchResult, 0, len(results))
		for _, r := range results {
			if r.Score >= req.MinScore {
				filtered = append(filtered, r)
			}
		}
		results = filtered
	}

	m.recordAccessAsync(req.SessionID, results)

	// Auto-attach observations if requested
	if req.IncludeObservations && len(results) > 0 {
		parentIDs := make([]string, len(results))
		for i, r := range results {
			parentIDs[i] = r.Node.ID
		}
		observations, err := m.store.GetObservationsForParents(ctx, parentIDs)
		if err == nil && len(observations) > 0 {
			obsByParent := make(map[string][]*MemoryNode)
			for _, obs := range observations {
				for _, pID := range obs.ParentIDs {
					obsByParent[pID] = append(obsByParent[pID], obs)
				}
			}
			for _, r := range results {
				if obsList, ok := obsByParent[r.Node.ID]; ok {
					r.Observations = obsList
				}
			}
		}
	}

	return results, nil
}

// GetByDedupHash finds an existing observation by its deterministic hash.
func (m *Manager) GetByDedupHash(ctx context.Context, dedupHash string) (*MemoryNode, error) {
	return m.store.GetByDedupHash(ctx, dedupHash)
}

// ResolveObservation marks a derived observation as resolved.
func (m *Manager) ResolveObservation(ctx context.Context, id string) error {
	return m.store.ResolveObservation(ctx, id)
}

// ListObservations returns observations matching criteria.
func (m *Manager) ListObservations(ctx context.Context, sessionID string, lensName string, status string, minSeverity string, limit int) ([]*MemoryNode, error) {
	return m.store.ListObservations(ctx, sessionID, lensName, status, minSeverity, limit)
}

// Vacuum compacts database files, checkpoints the WAL, and cleans expired TTL memories.
func (m *Manager) Vacuum(ctx context.Context) error {
	_, _ = m.store.PurgeExpired(ctx)
	return m.store.Vacuum(ctx)
}

// PurgeExpired cleans up any memories that have exceeded their designated TTL.
func (m *Manager) PurgeExpired(ctx context.Context) (int, error) {
	return m.store.PurgeExpired(ctx)
}

// Scratchpad returns access to the working memory layer.
func (m *Manager) Scratchpad() Scratchpad {
	return m.scratchpad
}

// Count returns the number of memories matching a session prefix.
func (m *Manager) Count(ctx context.Context, sessionPrefix string) (int, error) {
	return m.store.Count(ctx, sessionPrefix)
}

// VerifySessionChain audits the cryptographic Merkle chain for a given session.
func (m *Manager) VerifySessionChain(ctx context.Context, sessionID string) (bool, int, string, error) {
	return m.store.VerifySessionChain(ctx, sessionID)
}

// Close stops background access coalescing and releases the underlying store resources.
func (m *Manager) Close() error {
	m.closeOnce.Do(func() {
		if m.accessStop != nil {
			close(m.accessStop)
			m.accessWg.Wait()
		}
	})
	return m.store.Close()
}

// sanitizeText applies NFKC Unicode normalization and strips invisible or zero-width runes.
func sanitizeText(input string) string {
	// NFKC normalization
	normalized := norm.NFKC.String(input)

	// Strip zero-width runes (U+200B to U+200F, U+FEFF)
	var sb strings.Builder
	for _, r := range normalized {
		if (r >= 0x200B && r <= 0x200F) || r == 0xFEFF || unicode.IsControl(r) && r != '\n' && r != '\t' && r != '\r' {
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

func generateID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "mem_" + hex.EncodeToString(b)
}
