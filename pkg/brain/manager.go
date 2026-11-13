package brain

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
	"unicode"
	"golang.org/x/text/unicode/norm"
)

// RememberRequest specifies input parameters for storing a memory.
type RememberRequest struct {
	SessionID  string            `json:"session_id"`
	Category   string            `json:"category"`
	Content    string            `json:"content"`
	Provenance ProvenanceTier    `json:"provenance"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// RecallRequest specifies query parameters for retrieving memories.
type RecallRequest struct {
	SessionID  string         `json:"session_id,omitempty"`
	Category   string         `json:"category,omitempty"`
	Query      string         `json:"query"`
	Limit      int            `json:"limit,omitempty"`
	MinScore   float32        `json:"min_score,omitempty"`
	Provenance ProvenanceTier `json:"provenance,omitempty"`
}

// Manager orchestrates the cognitive memory store, embedder, and scratchpad.
type Manager struct {
	store      MemoryStore
	embedder   Embedder
	scratchpad Scratchpad
}

// NewManager creates a new brain manager.
func NewManager(store MemoryStore, embedder Embedder, scratchpad Scratchpad) *Manager {
	return &Manager{
		store:      store,
		embedder:   embedder,
		scratchpad: scratchpad,
	}
}

// Remember sanitizes, embeds, and stores a new memory node.
func (m *Manager) Remember(ctx context.Context, req RememberRequest) (*MemoryNode, error) {
	if strings.TrimSpace(req.Content) == "" {
		return nil, fmt.Errorf("content cannot be empty")
	}

	// Normalize content via NFKC and strip invisible runes (Stormcage cognitive firewall invariant)
	normalized := sanitizeText(req.Content)

	if req.Category == "" {
		req.Category = "general"
	}
	if req.Provenance == "" {
		req.Provenance = ProvenanceLocalWorkspace
	}
	if req.SessionID == "" {
		req.SessionID = "default"
	}

	// Generate embedding vector
	vec, err := m.embedder.Embed(ctx, normalized)
	if err != nil {
		return nil, fmt.Errorf("embedding generation failed: %w", err)
	}

	id := generateID()
	now := time.Now()

	node := &MemoryNode{
		ID:         id,
		SessionID:  req.SessionID,
		Category:   req.Category,
		Content:    normalized,
		Vector:     vec,
		Provenance: req.Provenance,
		Metadata:   req.Metadata,
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	if err := m.store.Store(ctx, node); err != nil {
		return nil, fmt.Errorf("failed to persist memory node: %w", err)
	}

	return node, nil
}

// Recall performs semantic similarity search over stored memory nodes.
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
		SessionID:  req.SessionID,
		Category:   req.Category,
		Provenance: req.Provenance,
		MinScore:   req.MinScore,
		Limit:      req.Limit,
	}

	return m.store.RecallSemantic(ctx, queryVec, filter)
}

// Scratchpad returns access to the working memory layer.
func (m *Manager) Scratchpad() Scratchpad {
	return m.scratchpad
}

// Count returns the number of memories matching a session prefix.
func (m *Manager) Count(ctx context.Context, sessionPrefix string) (int, error) {
	return m.store.Count(ctx, sessionPrefix)
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
