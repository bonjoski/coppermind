package brain

import (
	"context"
	"time"
)

// ProvenanceTier defines the security and trust classification of ingested context.
type ProvenanceTier string

const (
	ProvenanceLocalWorkspace ProvenanceTier = "TRUST_LOCAL_WORKSPACE"
	ProvenanceExternalUser   ProvenanceTier = "TAINT_EXTERNAL_USER"
	ProvenanceUntrustedWeb   ProvenanceTier = "TAINT_UNTRUSTED_WEB"
)

// MemoryNode represents an atomic unit of episodic or semantic memory.
type MemoryNode struct {
	ID         string            `json:"id"`
	SessionID  string            `json:"session_id"`
	Category   string            `json:"category"` // e.g. "architecture", "convention", "decision", "runbook", "observation"
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
}

// SearchResult contains a retrieved memory node and its relevance score.
type SearchResult struct {
	Node         *MemoryNode   `json:"node"`
	Score        float32       `json:"score"` // Cosine similarity: [0.0, 1.0]
	Observations []*MemoryNode `json:"observations,omitempty"`
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
