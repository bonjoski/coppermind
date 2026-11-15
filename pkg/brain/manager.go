package brain

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/bonjoski/coppermind/pkg/authz"
	"github.com/bonjoski/coppermind/pkg/gitscope"
	"github.com/bonjoski/coppermind/pkg/security"
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
}

// EventHook is invoked when a canonical memory is successfully stored.
type EventHook func(ctx context.Context, topic string, node *MemoryNode)

// Manager orchestrates the cognitive memory store, embedder, and scratchpad.
type Manager struct {
	store      MemoryStore
	embedder   Embedder
	scratchpad Scratchpad
	eventHook  EventHook
}

// NewManager creates a new brain manager.
func NewManager(store MemoryStore, embedder Embedder, scratchpad Scratchpad) *Manager {
	return &Manager{
		store:      store,
		embedder:   embedder,
		scratchpad: scratchpad,
	}
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

	// 1. Secret & Credential Scan (Fail-closed or sanitize)
	secRes, err := security.SanitizeMemory(req.Content)
	if err != nil {
		return nil, fmt.Errorf("memory rejected: %w", err)
	}

	// 2. Normalize content via NFKC and strip invisible runes (Stormcage cognitive firewall invariant)
	normalized := sanitizeText(secRes.SanitizedText)

	// 3. Cognitive Firewall Scan (OWASP LLM01 Prompt Injection & Jailbreak Defense)
	threatRes, err := security.InspectCognitiveThreats(normalized)
	if err != nil {
		return nil, fmt.Errorf("cognitive threat inspection failed: %w", err)
	}
	if threatRes.IsCritical && req.Provenance != ProvenanceLocalWorkspace {
		return nil, fmt.Errorf("untrusted input rejected: %w", security.ErrPromptInjectionRejected)
	}

	if req.Category == "" {
		req.Category = "general"
	}
	if req.Provenance == "" {
		req.Provenance = ProvenanceLocalWorkspace
	}
	if req.SessionID == "" {
		req.SessionID = "default"
	}

	metadata := req.Metadata
	if secRes.RedactedCount > 0 {
		if metadata == nil {
			metadata = make(map[string]string)
		}
		metadata["redacted_secrets"] = fmt.Sprintf("%d", secRes.RedactedCount)
	}
	if len(threatRes.Flags) > 0 {
		if metadata == nil {
			metadata = make(map[string]string)
		}
		metadata["firewall_flags"] = strings.Join(threatRes.Flags, ",")
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

	// 5. Intelligent Near-Duplicate Deduplication: Check if identical content exists in session if requested
	if req.Deduplicate {
		existing, _ := m.store.RecallSemantic(ctx, vec, MemoryFilter{
			SessionID: req.SessionID,
			Category:  req.Category,
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

	node := &MemoryNode{
		ID:              id,
		SessionID:       req.SessionID,
		Category:        req.Category,
		Content:         normalized,
		Vector:          vec,
		Provenance:      req.Provenance,
		TaintScore:      threatRes.TaintScore,
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
	}

	type superseder interface {
		Supersede(ctx context.Context, supersedingNode *MemoryNode, targetID string, rationale, advisoryRef string, authorIdentity, authorRole string) error
	}

	if req.SupersedesID != "" {
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

	normalizedQuery := sanitizeText(req.Query)
	queryVec, err := m.embedder.Embed(ctx, normalizedQuery)
	if err != nil {
		return nil, fmt.Errorf("embedding generation failed: %w", err)
	}

	filter := MemoryFilter{
		SessionID:           req.SessionID,
		Category:            req.Category,
		Provenance:          req.Provenance,
		MinScore:            req.MinScore,
		Limit:               req.Limit,
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

	// Apply Epistemic Authority tier weighting boost (RFC-2026-11-15-33)
	for _, r := range results {
		weight := float32(1.0)
		switch r.Node.AuthorityTier {
		case "TIER_0_SOVEREIGN":
			weight = 1.25
		case "TIER_1_ARCHITECTURE", "TIER_2_PRODUCT":
			weight = 1.00
		case "TIER_3_EPISODIC":
			weight = 0.75
		case "TIER_4_SCRATCHPAD":
			weight = 0.50
		}
		r.Score *= weight
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].Score > results[j].Score
	})

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

// Close releases the underlying store resources.
func (m *Manager) Close() error {
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
