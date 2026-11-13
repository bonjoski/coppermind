package brain

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
	"unicode"

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
}

// RecallRequest specifies query parameters for retrieving memories.
type RecallRequest struct {
	SessionID  string         `json:"session_id,omitempty"`
	Category   string         `json:"category,omitempty"`
	Query      string         `json:"query"`
	Limit      int            `json:"limit,omitempty"`
	MinScore   float32        `json:"min_score,omitempty"`
	Provenance ProvenanceTier `json:"provenance,omitempty"`
	Hybrid     bool           `json:"hybrid,omitempty"`
	GitRepo    string         `json:"git_repo,omitempty"`
	GitBranch  string         `json:"git_branch,omitempty"`
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

	node := &MemoryNode{
		ID:         id,
		SessionID:  req.SessionID,
		Category:   req.Category,
		Content:    normalized,
		Vector:     vec,
		Provenance: req.Provenance,
		TaintScore: threatRes.TaintScore,
		Metadata:   metadata,
		CreatedAt:  now,
		UpdatedAt:  now,
		ExpiresAt:  expiresAt,
	}

	if err := m.store.Store(ctx, node); err != nil {
		return nil, fmt.Errorf("failed to persist memory node: %w", err)
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
		SessionID:  req.SessionID,
		Category:   req.Category,
		Provenance: req.Provenance,
		MinScore:   req.MinScore,
		Limit:      req.Limit,
		Hybrid:     req.Hybrid,
		GitRepo:    req.GitRepo,
		GitBranch:  req.GitBranch,
	}

	if req.Hybrid {
		return m.store.RecallHybrid(ctx, normalizedQuery, queryVec, filter)
	}

	return m.store.RecallSemantic(ctx, queryVec, filter)
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
