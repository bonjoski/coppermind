package scratchpad

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// HandoffPacket structures cross-agent working memory handoffs so parallel worktrees
// never repeat already-disproved dead-ends or lose context on compaction.
type HandoffPacket struct {
	AgentID       string    `json:"agent_id"`
	Worktree      string    `json:"worktree"`
	Goal          string    `json:"goal"`
	TouchedFiles  []string  `json:"touched_files,omitempty"`
	VerifiedFacts []string  `json:"verified_facts,omitempty"`
	DeadEndsTried []string  `json:"dead_ends_tried,omitempty"`
	NextStep      string    `json:"next_step"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// HandoffKey returns the canonical scratchpad key for a worktree handoff packet.
func HandoffKey(worktree string) string {
	w := strings.TrimSpace(worktree)
	if w == "" {
		w = "default"
	}
	return "handoff:" + w
}

// EncodeHandoff serializes a HandoffPacket into JSON for scratchpad storage.
func EncodeHandoff(pkt HandoffPacket) (string, error) {
	if pkt.UpdatedAt.IsZero() {
		pkt.UpdatedAt = time.Now().UTC()
	}
	b, err := json.Marshal(pkt)
	if err != nil {
		return "", fmt.Errorf("failed encoding handoff packet: %w", err)
	}
	return string(b), nil
}

// DecodeHandoff parses a JSON handoff packet from scratchpad storage.
func DecodeHandoff(raw string) (*HandoffPacket, error) {
	var pkt HandoffPacket
	if err := json.Unmarshal([]byte(raw), &pkt); err != nil {
		return nil, fmt.Errorf("failed decoding handoff packet: %w", err)
	}
	return &pkt, nil
}

// CASScratchpad is implemented by scratchpads supporting atomic CompareAndSwap.
type CASScratchpad interface {
	CompareAndSwap(ctx context.Context, key, expectedVal, newVal string, ttl time.Duration) (bool, error)
}
