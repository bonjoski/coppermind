package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

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

// EnqueuePendingTicket inserts a deduplicated pending lens ticket through the single-writer ring.
func (s *SQLiteStore) EnqueuePendingTicket(ctx context.Context, ticket PendingLensTicket) error {
	if strings.TrimSpace(ticket.LensName) == "" || strings.TrimSpace(ticket.MemoryID) == "" {
		return fmt.Errorf("lens_name and memory_id are required")
	}
	if ticket.ID == "" {
		sum := sha256.Sum256([]byte(ticket.LensName + ":" + ticket.MemoryID))
		ticket.ID = "tkt_" + hex.EncodeToString(sum[:8])
	}
	if ticket.Status == "" {
		ticket.Status = "pending"
	}
	if ticket.CreatedAt.IsZero() {
		ticket.CreatedAt = time.Now()
	}
	sinksJSON, _ := json.Marshal(ticket.MatchedSinks)
	if ticket.MatchedSinks == nil {
		sinksJSON = []byte("[]")
	}

	return s.RunWriteTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.Exec(`
			INSERT INTO pending_lens_tickets (
				id, lens_name, commit_sha, memory_id, repo_name, branch_name, summary, matched_sinks_json, status, created_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT DO NOTHING
		`, ticket.ID, ticket.LensName, ticket.CommitSHA, ticket.MemoryID, ticket.RepoName, ticket.BranchName,
			ticket.Summary, string(sinksJSON), ticket.Status, ticket.CreatedAt.UnixNano())
		return err
	})
}

// ListPendingTickets returns inbox tickets filtered by optional lensName and status.
func (s *SQLiteStore) ListPendingTickets(ctx context.Context, lensName, status string, limit int) ([]PendingLensTicket, error) {
	if limit <= 0 || limit > 100 {
		limit = 25
	}
	query := `SELECT id, lens_name, commit_sha, memory_id, repo_name, branch_name, summary, matched_sinks_json, status, created_at, resolved_at FROM pending_lens_tickets WHERE 1=1`
	var args []any
	if lensName != "" && lensName != "all" {
		query += " AND lens_name = ?"
		args = append(args, lensName)
	}
	if status != "" {
		query += " AND status = ?"
		args = append(args, status)
	}
	query += " ORDER BY created_at ASC LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []PendingLensTicket
	for rows.Next() {
		var t PendingLensTicket
		var sinksJSON string
		var createdNano int64
		var resolvedNano sql.NullInt64
		if err := rows.Scan(&t.ID, &t.LensName, &t.CommitSHA, &t.MemoryID, &t.RepoName, &t.BranchName, &t.Summary, &sinksJSON, &t.Status, &createdNano, &resolvedNano); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(sinksJSON), &t.MatchedSinks)
		t.CreatedAt = time.Unix(0, createdNano)
		if resolvedNano.Valid {
			rt := time.Unix(0, resolvedNano.Int64)
			t.ResolvedAt = &rt
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// PeekOldestPendingTicket returns the oldest pending ticket for lensName (or any lens if empty).
func (s *SQLiteStore) PeekOldestPendingTicket(ctx context.Context, lensName string) (*PendingLensTicket, error) {
	tickets, err := s.ListPendingTickets(ctx, lensName, "pending", 1)
	if err != nil {
		return nil, err
	}
	if len(tickets) == 0 {
		return nil, nil
	}
	return &tickets[0], nil
}

// ResolvePendingTicket marks a pending ticket completed or dismissed atomically via single-writer ring.
func (s *SQLiteStore) ResolvePendingTicket(ctx context.Context, id, newStatus string) error {
	if newStatus != "completed" && newStatus != "dismissed" {
		return fmt.Errorf("invalid ticket status %q (must be completed or dismissed)", newStatus)
	}
	nowNano := time.Now().UnixNano()
	return s.RunWriteTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE pending_lens_tickets SET status = ?, resolved_at = ? WHERE id = ?`, newStatus, nowNano, id)
		return err
	})
}

// ResolvePendingTicketsByMemory marks pending tickets matching (lensName, memoryID) completed.
func (s *SQLiteStore) ResolvePendingTicketsByMemory(ctx context.Context, lensName, memoryID string) error {
	nowNano := time.Now().UnixNano()
	return s.RunWriteTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE pending_lens_tickets SET status = 'completed', resolved_at = ? WHERE lens_name = ? AND memory_id = ? AND status = 'pending'`,
			nowNano, lensName, memoryID)
		return err
	})
}
