package storage

import (
	"context"
	"time"

	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/graph"
	"github.com/bonjoski/coppermind/pkg/scope"
)

// IndexedFileRecord tracks content hashes and stored chunk IDs for incremental codebase & vault sync.
type IndexedFileRecord struct {
	RepoRoot      string    `json:"repo_root"`
	RelPath       string    `json:"rel_path"`
	ContentSHA256 string    `json:"content_sha256"`
	ChunkIDs      []string  `json:"chunk_ids"`
	IndexedAt     time.Time `json:"indexed_at"`
}

// PendingLensTicket represents a pre-filtered commit or artifact awaiting zero-key host lens evaluation.
type PendingLensTicket struct {
	ID           string     `json:"id"`
	LensName     string     `json:"lens_name"`
	CommitSHA    string     `json:"commit_sha,omitempty"`
	MemoryID     string     `json:"memory_id"`
	RepoName     string     `json:"repo_name,omitempty"`
	BranchName   string     `json:"branch_name,omitempty"`
	Summary      string     `json:"summary"`
	MatchedSinks []string   `json:"matched_sinks,omitempty"`
	Status       string     `json:"status"` // pending | completed | dismissed
	CreatedAt    time.Time  `json:"created_at"`
	ResolvedAt   *time.Time `json:"resolved_at,omitempty"`
}

// ReindexStats reports outcomes from a vector re-embedding upgrade pass.
type ReindexStats struct {
	TotalNodes int           `json:"total_nodes"`
	Reindexed  int           `json:"reindexed"`
	Skipped    int           `json:"skipped"`
	ModelName  string        `json:"model_name"`
	Dimension  int           `json:"dimension"`
	Duration   time.Duration `json:"duration"`
}

// VectorCoverage summarizes how many active vault nodes match a given model name.
type VectorCoverage struct {
	TotalNodes    int            `json:"total_nodes"`
	MatchingNodes int            `json:"matching_nodes"`
	ByModel       map[string]int `json:"by_model"`
}

// TimelineFilter scopes chronological memory timeline queries across backends.
type TimelineFilter struct {
	Since     *time.Time
	Repo      string
	Scope     string
	ScopeMode scope.Mode
	Limit     int
}

// ScopeSummary reports memory and architectural invariant counts for a canonical scope.
type ScopeSummary struct {
	Scope          string `json:"scope"`
	Depth          int    `json:"depth"`
	MemoryCount    int    `json:"memory_count"`
	InvariantCount int    `json:"invariant_count"`
}

// CartridgeFilter selects active, non-derived nodes for selective .capsule v2 exports.
type CartridgeFilter struct {
	Repo      string
	Category  string
	Tier      string
	Scope     string
	ScopeMode scope.Mode
	Since     *time.Time
}

// SupersessionAudit is a backend-agnostic supersession audit trail entry.
type SupersessionAudit struct {
	ID             string    `json:"id"`
	SupersedingID  string    `json:"superseding_id"`
	SupersededID   string    `json:"superseded_id"`
	Rationale      string    `json:"rationale"`
	AdvisoryRef    string    `json:"advisory_ref"`
	AuthorIdentity string    `json:"author_identity"`
	AuthorRole     string    `json:"author_role"`
	CreatedAt      time.Time `json:"created_at"`
}

// GraphStore is implemented by both SQLite (Profile A) and PostgreSQL (Profile B) stores.
type GraphStore interface {
	StoreEdges(ctx context.Context, edges []graph.Edge) error
	GetEdgesForNode(ctx context.Context, nodeID string) ([]graph.Edge, error)
	GetNodesByEntity(ctx context.Context, entity string, limit int) ([]*brain.MemoryNode, error)
	ImpactForFile(ctx context.Context, relPath string, limit int) ([]*brain.MemoryNode, error)
	ExpandGraphNeighbors(ctx context.Context, seedIDs []string, maxHops int, filter brain.MemoryFilter) ([]*brain.SearchResult, error)
	GetGraphSubgraph(ctx context.Context, centerID string, maxNodes int, maxEdges int) ([]*brain.MemoryNode, []graph.Edge, error)
}

// IndexedFileStore tracks hash-incremental code and Obsidian/Markdown vault sync manifests.
type IndexedFileStore interface {
	ListIndexedFiles(ctx context.Context, repoRoot string) (map[string]IndexedFileRecord, error)
	UpsertIndexedFile(ctx context.Context, rec IndexedFileRecord) error
	DeleteIndexedChunks(ctx context.Context, chunkIDs []string) error
	PruneIndexedFile(ctx context.Context, repoRoot, relPath string, chunkIDs []string) error
}

// InboxStore manages zero-API-key pending commit lens review tickets.
type InboxStore interface {
	EnqueuePendingTicket(ctx context.Context, ticket PendingLensTicket) error
	ListPendingTickets(ctx context.Context, lensName, status string, limit int) ([]PendingLensTicket, error)
	PeekOldestPendingTicket(ctx context.Context, lensName string) (*PendingLensTicket, error)
	ResolvePendingTicket(ctx context.Context, id, newStatus string) error
	ResolvePendingTicketsByMemory(ctx context.Context, lensName, memoryID string) error
}

// VectorAdminStore reports embedding coverage and performs micro-batched vector re-indexing.
type VectorAdminStore interface {
	GetVectorCoverage(ctx context.Context, activeModel string) (*VectorCoverage, error)
	ReindexVectors(ctx context.Context, emb brain.Embedder, modelName string, batchSize int, dryRun bool) (*ReindexStats, error)
}

// ExplorerStore powers Brain Explorer v2 timeline, proposals, scopes, and supersession lineage across backends.
type ExplorerStore interface {
	ListTimeline(ctx context.Context, filter TimelineFilter) ([]*brain.MemoryNode, error)
	ListProposals(ctx context.Context, limit int) ([]*brain.MemoryNode, error)
	GetLineage(ctx context.Context, id string) ([]*brain.MemoryNode, []*SupersessionAudit, error)
	ListScopes(ctx context.Context) ([]ScopeSummary, error)
}

// CartridgeStore provides selective filtered exports and SHA-256 dedup sets for .capsule v2 cartridges.
type CartridgeStore interface {
	QueryActiveNodesForCartridge(ctx context.Context, filter CartridgeFilter) ([]*brain.MemoryNode, error)
	ListExistingContentHashes(ctx context.Context) (map[string]bool, error)
}
