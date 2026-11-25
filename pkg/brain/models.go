package brain

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/bonjoski/coppermind/pkg/scope"
	stormtaint "github.com/bonjoski/stormcage/pkg/taint"
)

// ProvenanceTier defines the security and trust classification of ingested context.
type ProvenanceTier string

const (
	ProvenanceLocalWorkspace ProvenanceTier = "TRUST_LOCAL_WORKSPACE"
	ProvenanceSharedDoc      ProvenanceTier = "TAINT_SHARED_DOC"
	ProvenanceExternalUser   ProvenanceTier = "TAINT_EXTERNAL_USER"
	ProvenanceUntrustedWeb   ProvenanceTier = "TAINT_UNTRUSTED_WEB"
)

// ParseProvenanceTier validates and normalizes a provenance tier string.
func ParseProvenanceTier(raw string) (ProvenanceTier, error) {
	switch ProvenanceTier(strings.ToUpper(strings.TrimSpace(raw))) {
	case ProvenanceLocalWorkspace:
		return ProvenanceLocalWorkspace, nil
	case ProvenanceSharedDoc:
		return ProvenanceSharedDoc, nil
	case ProvenanceExternalUser:
		return ProvenanceExternalUser, nil
	case ProvenanceUntrustedWeb:
		return ProvenanceUntrustedWeb, nil
	default:
		return "", fmt.Errorf("invalid provenance tier %q (expected TRUST_LOCAL_WORKSPACE, TAINT_SHARED_DOC, TAINT_EXTERNAL_USER, or TAINT_UNTRUSTED_WEB)", raw)
	}
}

// ToStormcageTaint maps Coppermind's ProvenanceTier to Stormcage's canonical TaintLevel.
// Unknown or spoofed tiers fail closed to TAINT_UNTRUSTED_WEB.
func (p ProvenanceTier) ToStormcageTaint() stormtaint.TaintLevel {
	switch p {
	case ProvenanceLocalWorkspace:
		return stormtaint.TRUST_LOCAL_WORKSPACE
	case ProvenanceSharedDoc:
		return stormtaint.TAINT_SHARED_DOC
	case ProvenanceExternalUser:
		return stormtaint.TAINT_EXTERNAL_USER
	case ProvenanceUntrustedWeb:
		return stormtaint.TAINT_UNTRUSTED_WEB
	default:
		return stormtaint.TAINT_UNTRUSTED_WEB
	}
}

// MemoryNode represents an atomic unit of episodic or semantic memory.
type MemoryNode struct {
	ID         string            `json:"id"`
	SessionID  string            `json:"session_id"`
	Category   string            `json:"category"` // e.g. "architecture", "convention", "decision", "learning", "architectural-learning", "runbook", "observation"
	Content    string            `json:"content"`
	Vector     []float32         `json:"vector,omitempty"`
	Provenance ProvenanceTier    `json:"provenance"`
	TaintScore float64           `json:"taint_score"`
	Metadata   map[string]string `json:"metadata,omitempty"`
	PrevHash   string            `json:"prev_hash"`
	Hash       string            `json:"hash"`
	CreatedAt  time.Time         `json:"created_at"`
	UpdatedAt  time.Time         `json:"updated_at"`
	ExpiresAt  *time.Time        `json:"expires_at,omitempty"`

	// Cognitive Lenses extensions
	Derived    bool     `json:"derived"`               // If true, derived from a cognitive lens (anti-recursion invariant)
	SourceLens string   `json:"source_lens,omitempty"` // Name of the originating lens (e.g. "security-architect")
	ParentIDs  []string `json:"parent_ids,omitempty"`  // Linked canonical memories analyzed by the lens
	Severity   string   `json:"severity,omitempty"`    // "info", "low", "medium", "high", "critical"
	Status     string   `json:"status,omitempty"`      // "open", "resolved"
	DedupHash  string   `json:"dedup_hash,omitempty"`  // Deterministic deduplication hash

	// Epistemic Authority & Profile B Lifecycle extensions (RFC-2026-11-15-33)
	AuthorityTier   string `json:"authority_tier,omitempty"`   // "TIER_0_SOVEREIGN", "TIER_1_ARCHITECTURE", "TIER_2_PRODUCT", "TIER_3_EPISODIC", "TIER_4_SCRATCHPAD"
	LifecycleStatus string `json:"lifecycle_status,omitempty"` // "ACTIVE", "SUPERSEDED", "PROPOSED", "REJECTED", "DEPRECATED"
	AuthorIdentity  string `json:"author_identity,omitempty"`
	AuthorRole      string `json:"author_role,omitempty"`
	SupersededByID  string `json:"superseded_by_id,omitempty"`
	SupersedesID    string `json:"supersedes_id,omitempty"`
	Rationale       string `json:"rationale,omitempty"`
	AdvisoryRef     string `json:"advisory_ref,omitempty"`

	// Cognitive Core v0.7 extensions (RFC-2026-11-24-55)
	EmbeddingModel string    `json:"embedding_model,omitempty"`
	EmbeddingDim   int       `json:"embedding_dim,omitempty"`
	AccessCount    int       `json:"access_count,omitempty"`
	LastAccessedAt time.Time `json:"last_accessed_at,omitempty"`
	ContentSHA256  string    `json:"content_sha256,omitempty"`

	// Hierarchical Scope extension (RFC-2026-11-24-58): "" = vault-global, e.g. "platform/payments/webhooks"
	Scope string `json:"scope,omitempty"`
}

// ConflictWarning alerts callers when a newly stored architectural memory may conflict
// with an existing active TIER_0/TIER_1 invariant.
type ConflictWarning struct {
	ConflictingNodeID string  `json:"conflicting_node_id"`
	AuthorityTier     string  `json:"authority_tier"`
	Similarity        float32 `json:"similarity"`
	Summary           string  `json:"summary"`
	SuggestedAction   string  `json:"suggested_action"`
}

// MemoryFilter specifies search criteria for recall operations.
type MemoryFilter struct {
	SessionID           string         `json:"session_id,omitempty"`
	Category            string         `json:"category,omitempty"`
	Provenance          ProvenanceTier `json:"provenance,omitempty"`
	MinScore            float32        `json:"min_score,omitempty"`
	Limit               int            `json:"limit,omitempty"`
	Hybrid              bool           `json:"hybrid,omitempty"`
	GitRepo             string         `json:"git_repo,omitempty"`
	GitBranch           string         `json:"git_branch,omitempty"`
	Derived             *bool          `json:"derived,omitempty"`
	SourceLens          string         `json:"source_lens,omitempty"`
	Severity            string         `json:"severity,omitempty"`
	Status              string         `json:"status,omitempty"`
	IncludeObservations bool           `json:"include_observations,omitempty"`
	ParentID            string         `json:"parent_id,omitempty"`

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

// SearchResult contains a retrieved memory node and its relevance score.
type SearchResult struct {
	Node         *MemoryNode     `json:"node"`
	Score        float32         `json:"score"` // Normalized composite relevance: [0.0, 1.0]
	Observations []*MemoryNode   `json:"observations,omitempty"`
	Breakdown    *ScoreBreakdown `json:"breakdown,omitempty"`
	GraphLinks   []string        `json:"graph_links,omitempty"`
}

// MemoryStore defines the persistent storage layer for cognitive memories.
type MemoryStore interface {
	// Store persists a memory node.
	Store(ctx context.Context, node *MemoryNode) error

	// RecallSemantic searches memories via cosine similarity against a query vector.
	RecallSemantic(ctx context.Context, queryVector []float32, filter MemoryFilter) ([]*SearchResult, error)

	// RecallHybrid searches memories using combined FTS5 BM25 keyword matching and vector cosine similarity.
	RecallHybrid(ctx context.Context, query string, queryVector []float32, filter MemoryFilter) ([]*SearchResult, error)

	// RecallEpisodic retrieves chronologically ordered memory nodes for a session.
	RecallEpisodic(ctx context.Context, sessionID string, limit int) ([]*MemoryNode, error)

	// Delete removes a memory node by ID.
	Delete(ctx context.Context, id string) error

	// Count returns the count of memory nodes, optionally filtered by session prefix.
	Count(ctx context.Context, sessionPrefix string) (int, error)

	// PurgeExpired removes memories that have exceeded their TTL.
	PurgeExpired(ctx context.Context) (int, error)

	// Vacuum compacts storage, checkpoints WAL, and reclaims disk pages.
	Vacuum(ctx context.Context) error

	// VerifySessionChain audits the cryptographic Merkle chain for a given session.
	// Returns true and the verified count if intact, or false with the offending node ID and error if tampered.
	VerifySessionChain(ctx context.Context, sessionID string) (bool, int, string, error)

	// GetByID retrieves a memory node by its ID.
	GetByID(ctx context.Context, id string) (*MemoryNode, error)

	// GetByDedupHash retrieves an unresolved observation by its deterministic dedup hash.
	GetByDedupHash(ctx context.Context, dedupHash string) (*MemoryNode, error)

	// GetObservationsForParents retrieves all active observations linked to the given parent memory IDs.
	GetObservationsForParents(ctx context.Context, parentIDs []string) ([]*MemoryNode, error)

	// ResolveObservation marks an observation as resolved.
	ResolveObservation(ctx context.Context, id string) error

	// ListObservations retrieves observations filtered by session, lens, status, and minSeverity.
	ListObservations(ctx context.Context, sessionID string, lensName string, status string, minSeverity string, limit int) ([]*MemoryNode, error)

	// Close releases any database connections or locks.
	Close() error
}

// Embedder generates vector embeddings from text.
type Embedder interface {
	// Embed produces a normalized float32 vector for the given text.
	Embed(ctx context.Context, text string) ([]float32, error)

	// Dimension returns the dimensionality of vectors produced by this embedder.
	Dimension() int
}

// Scratchpad defines working memory for fast ephemeral key-value state and locking.
type Scratchpad interface {
	Get(ctx context.Context, key string) (string, bool)
	Set(ctx context.Context, key string, val string, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
	AcquireLock(ctx context.Context, lockName string, ttl time.Duration) (unlock func(), err error)
	Keys(ctx context.Context) []string
}
