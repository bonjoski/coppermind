package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/bonjoski/coppermind/pkg/authz"
	"github.com/bonjoski/coppermind/pkg/brain"
)

// SupersessionRecord models an immutable audit entry when a memory node is superseded.
type SupersessionRecord struct {
	ID             string    `json:"id"`
	SupersedingID  string    `json:"superseding_id"`
	SupersededID   string    `json:"superseded_id"`
	Rationale      string    `json:"rationale"`
	AdvisoryRef    string    `json:"advisory_ref"`
	AuthorIdentity string    `json:"author_identity"`
	AuthorRole     string    `json:"author_role"`
	CreatedAt      time.Time `json:"created_at"`
}

// Supersede atomically persists a new memory node that supersedes an existing node.
// It marks the target node as SUPERSEDED and records the supersession in memory_supersessions.
func (s *PostgresStore) Supersede(
	ctx context.Context,
	supersedingNode *brain.MemoryNode,
	targetID string,
	rationale, advisoryRef string,
	authorIdentity, authorRole string,
) error {
	if targetID == "" {
		return fmt.Errorf("target node ID cannot be empty")
	}
	if rationale == "" {
		return authz.ErrMissingRationale
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// 1. Verify target node exists and fetch its authority tier
	var targetTier, targetStatus string
	err = tx.QueryRowContext(ctx, "SELECT authority_tier, lifecycle_status FROM memory_nodes WHERE id = $1 FOR UPDATE", targetID).Scan(&targetTier, &targetStatus)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("target memory node %q not found: %w", targetID, err)
		}
		return fmt.Errorf("failed to query target memory node: %w", err)
	}

	targetTierParsed := authz.ParseAuthorityTier(targetTier)
	nodeTier := supersedingNode.AuthorityTier
	if nodeTier == "" {
		nodeTier = authz.TierToString(authz.CategoryToDefaultTier(supersedingNode.Category))
	}
	nodeTierParsed := authz.ParseAuthorityTier(nodeTier)
	if nodeTierParsed < targetTierParsed {
		return authz.ErrInvalidSupersession
	}

	// 2. Mark target node as SUPERSEDED
	nowNano := time.Now().UnixNano()
	_, err = tx.ExecContext(ctx, `
		UPDATE memory_nodes
		SET lifecycle_status = $1, superseded_by_id = $2, updated_at = $3
		WHERE id = $4
	`, string(authz.StatusSuperseded), supersedingNode.ID, nowNano, targetID)
	if err != nil {
		return fmt.Errorf("failed to update target memory node: %w", err)
	}

	// 3. Populate supersedingNode fields
	supersedingNode.SupersedesID = targetID
	supersedingNode.Rationale = rationale
	supersedingNode.AdvisoryRef = advisoryRef
	supersedingNode.AuthorIdentity = authorIdentity
	supersedingNode.AuthorRole = authorRole
	supersedingNode.LifecycleStatus = string(authz.StatusActive)
	if supersedingNode.AuthorityTier == "" {
		supersedingNode.AuthorityTier = targetTier
	}

	// 4. Store supersedingNode
	if err := s.Store(ctx, supersedingNode); err != nil {
		return fmt.Errorf("failed to store superseding memory node: %w", err)
	}

	// 5. Insert audit record in memory_supersessions
	supersessionID := fmt.Sprintf("sup-%s-%s", supersedingNode.ID, targetID)
	if len(supersessionID) > 64 {
		supersessionID = supersessionID[:64]
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO memory_supersessions (
			id, superseding_id, superseded_id, rationale, advisory_ref, author_identity, author_role, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (id) DO NOTHING
	`, supersessionID, supersedingNode.ID, targetID, rationale, advisoryRef, authorIdentity, authorRole, nowNano)
	if err != nil {
		return fmt.Errorf("failed to record memory supersession audit: %w", err)
	}

	return tx.Commit()
}

// GetAncestors retrieves all immediate predecessor memory IDs that the given node supersedes.
func (s *PostgresStore) GetAncestors(ctx context.Context, id string) ([]string, error) {
	query := `
		SELECT superseded_id
		FROM memory_supersessions
		WHERE superseding_id = $1
	`
	rows, err := s.db.QueryContext(ctx, query, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ancestors []string
	for rows.Next() {
		var anc string
		if err := rows.Scan(&anc); err != nil {
			return nil, err
		}
		ancestors = append(ancestors, anc)
	}
	return ancestors, rows.Err()
}

// GetSupersessionHistory retrieves the supersession audit trail for a memory node.
func (s *PostgresStore) GetSupersessionHistory(ctx context.Context, id string) ([]*SupersessionRecord, error) {
	query := `
		SELECT id, superseding_id, superseded_id, rationale, advisory_ref, author_identity, author_role, created_at
		FROM memory_supersessions
		WHERE superseding_id = $1 OR superseded_id = $1
		ORDER BY created_at ASC
	`
	rows, err := s.db.QueryContext(ctx, query, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []*SupersessionRecord
	for rows.Next() {
		var rec SupersessionRecord
		var createdAtNano int64
		if err := rows.Scan(
			&rec.ID, &rec.SupersedingID, &rec.SupersededID, &rec.Rationale,
			&rec.AdvisoryRef, &rec.AuthorIdentity, &rec.AuthorRole, &createdAtNano,
		); err != nil {
			return nil, err
		}
		rec.CreatedAt = time.Unix(0, createdAtNano)
		records = append(records, &rec)
	}
	return records, rows.Err()
}
