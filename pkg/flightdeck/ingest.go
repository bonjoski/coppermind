package flightdeck

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bonjoski/coppermind/pkg/authz"
	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/graph"
	"github.com/bonjoski/coppermind/pkg/security"
	"github.com/bonjoski/coppermind/pkg/storage"
)

const (
	// DefaultMaxTraceBytes caps Flightdeck JSONL ingestion at 16 MiB (anti-DoS).
	DefaultMaxTraceBytes = 16 * 1024 * 1024
)

var (
	// ErrTraceSymlinkRefused rejects symlinked trace files fail-closed.
	ErrTraceSymlinkRefused = errors.New("flightdeck security violation: symlinked trace file refused fail-closed")
	// ErrTraceTooLarge rejects oversized trace streams fail-closed.
	ErrTraceTooLarge = errors.New("flightdeck security violation: trace exceeds 16 MiB size cap")
)

// IngestOptions configures Flightdeck post-mortem ingestion.
type IngestOptions struct {
	SessionID    string // Defaults to "flightdeck"
	RepoName     string // Optional git_repo tag
	MaxFileBytes int64  // Defaults to 16 MiB
}

// TraceEvent models a single structured command/tool execution line from a Flightdeck JSONL trace.
type TraceEvent struct {
	Timestamp string `json:"timestamp"`
	TS        string `json:"ts"`
	Command   string `json:"command"`
	Cmd       string `json:"cmd"`
	Tool      string `json:"tool"`
	ExitCode  *int   `json:"exit_code"`
	Stderr    string `json:"stderr"`
	Error     string `json:"error"`
	Stdout    string `json:"stdout"`
	Cwd       string `json:"cwd"`
	Repo      string `json:"repo"`
}

func (e TraceEvent) commandText() string {
	if s := strings.TrimSpace(e.Command); s != "" {
		return s
	}
	if s := strings.TrimSpace(e.Cmd); s != "" {
		return s
	}
	return strings.TrimSpace(e.Tool)
}

func (e TraceEvent) errorText() string {
	if s := strings.TrimSpace(e.Stderr); s != "" {
		return s
	}
	return strings.TrimSpace(e.Error)
}

// IngestResult summarizes deterministic failure -> recovery post-mortem ingestion.
type IngestResult struct {
	EventsRead       int      `json:"events_read"`
	FailuresFound    int      `json:"failures_found"`
	PairsLinked      int      `json:"pairs_linked"`
	DeadEndIDs       []string `json:"dead_end_ids,omitempty"`
	FixIDs           []string `json:"fix_ids,omitempty"`
	QuarantinedCount int      `json:"quarantined_count"`
}

// IngestTrace deterministically extracts failed command episodes (exit_code != 0) paired with
// subsequent exit-0 recovery commands into sanitized dead_end + troubleshooting memories linked
// by a graph.RelCausedBy edge.
func IngestTrace(ctx context.Context, mgr *brain.Manager, tracePath string, opts IngestOptions) (*IngestResult, error) {
	if mgr == nil {
		return nil, fmt.Errorf("brain manager is required")
	}
	absPath, err := filepath.Abs(strings.TrimSpace(tracePath))
	if err != nil {
		return nil, err
	}
	fi, err := os.Lstat(absPath)
	if err != nil {
		return nil, fmt.Errorf("cannot access trace %q: %w", absPath, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: %s", ErrTraceSymlinkRefused, absPath)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("trace path %q is not a regular file", absPath)
	}

	maxBytes := opts.MaxFileBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxTraceBytes
	}
	if fi.Size() > maxBytes {
		return nil, fmt.Errorf("%w (%d bytes > %d)", ErrTraceTooLarge, fi.Size(), maxBytes)
	}

	f, err := os.Open(absPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	raw, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maxBytes {
		return nil, ErrTraceTooLarge
	}

	sessionID := strings.TrimSpace(opts.SessionID)
	if sessionID == "" {
		sessionID = "flightdeck"
	}

	var events []TraceEvent
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var ev TraceEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue // Ignore malformed telemetry lines deterministically
		}
		events = append(events, ev)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	graphStore, hasGraph := mgr.Store().(storage.GraphStore)
	res := &IngestResult{EventsRead: len(events)}

	var pendingFail *TraceEvent
	recordFailureOnly := func(ev *TraceEvent) {
		if ev == nil {
			return
		}
		id, ok := storeDeadEnd(ctx, mgr, sessionID, opts.RepoName, ev)
		if !ok {
			res.QuarantinedCount++
			return
		}
		res.DeadEndIDs = append(res.DeadEndIDs, id)
	}

	for i := range events {
		ev := &events[i]
		if ev.ExitCode == nil {
			continue
		}
		code := *ev.ExitCode
		if code != 0 {
			res.FailuresFound++
			if pendingFail != nil {
				recordFailureOnly(pendingFail)
			}
			pendingFail = ev
			continue
		}

		// Recovery command (exit_code == 0) following a failure!
		if pendingFail != nil {
			deadID, okDead := storeDeadEnd(ctx, mgr, sessionID, opts.RepoName, pendingFail)
			fixID, okFix := storeFix(ctx, mgr, sessionID, opts.RepoName, pendingFail, ev)
			if !okDead || !okFix {
				res.QuarantinedCount++
				pendingFail = nil
				continue
			}
			res.DeadEndIDs = append(res.DeadEndIDs, deadID)
			res.FixIDs = append(res.FixIDs, fixID)
			res.PairsLinked++

			if hasGraph {
				sum := sha256.Sum256([]byte(fixID + ":" + string(graph.RelCausedBy) + ":" + deadID))
				_ = graphStore.StoreEdges(ctx, []graph.Edge{{
					ID:        "edge_" + hex.EncodeToString(sum[:8]),
					SourceID:  fixID,
					TargetID:  deadID,
					Relation:  graph.RelCausedBy,
					Weight:    1.0,
					CreatedAt: time.Now().UTC(),
				}})
			}
			pendingFail = nil
		}
	}
	if pendingFail != nil {
		recordFailureOnly(pendingFail)
	}

	return res, nil
}

func storeDeadEnd(ctx context.Context, mgr *brain.Manager, sessionID, repoOverride string, fail *TraceEvent) (string, bool) {
	cmd := truncateStr(fail.commandText(), 300)
	errOut := truncateStr(fail.errorText(), 800)
	code := 1
	if fail.ExitCode != nil {
		code = *fail.ExitCode
	}
	raw := fmt.Sprintf("Flightdeck Dead End (exit %d): command `%s` failed.\nStderr: %s", code, cmd, errOut)
	secRes, err := security.SanitizeMemory(raw)
	if err != nil {
		return "", false
	}
	if threat, tErr := security.InspectCognitiveThreats(secRes.SanitizedText); tErr == nil && threat != nil && threat.IsCritical {
		return "", false
	}
	repo := strings.TrimSpace(repoOverride)
	if repo == "" {
		repo = strings.TrimSpace(fail.Repo)
	}
	meta := map[string]string{
		"source":    "flightdeck",
		"exit_code": fmt.Sprintf("%d", code),
	}
	if repo != "" {
		meta["git_repo"] = repo
	}
	if fail.Cwd != "" {
		meta["cwd"] = truncateStr(fail.Cwd, 200)
	}
	node, err := mgr.Remember(ctx, brain.RememberRequest{
		SessionID:     sessionID,
		Category:      "dead_end",
		Content:       secRes.SanitizedText,
		Provenance:    brain.ProvenanceLocalWorkspace,
		AuthorityTier: authz.TierName2MentorCapsule,
		Metadata:      meta,
	})
	if err != nil {
		return "", false
	}
	return node.ID, true
}

func storeFix(ctx context.Context, mgr *brain.Manager, sessionID, repoOverride string, fail, fix *TraceEvent) (string, bool) {
	failCmd := truncateStr(fail.commandText(), 240)
	fixCmd := truncateStr(fix.commandText(), 300)
	errHint := truncateStr(fail.errorText(), 300)
	raw := fmt.Sprintf("Flightdeck Recovery Fix: resolved failure of `%s` (%s) by running `%s` (exit 0).", failCmd, errHint, fixCmd)
	secRes, err := security.SanitizeMemory(raw)
	if err != nil {
		return "", false
	}
	if threat, tErr := security.InspectCognitiveThreats(secRes.SanitizedText); tErr == nil && threat != nil && threat.IsCritical {
		return "", false
	}
	repo := strings.TrimSpace(repoOverride)
	if repo == "" {
		repo = strings.TrimSpace(fix.Repo)
	}
	if repo == "" {
		repo = strings.TrimSpace(fail.Repo)
	}
	meta := map[string]string{
		"source":    "flightdeck",
		"exit_code": "0",
	}
	if repo != "" {
		meta["git_repo"] = repo
	}
	node, err := mgr.Remember(ctx, brain.RememberRequest{
		SessionID:     sessionID,
		Category:      "troubleshooting",
		Content:       secRes.SanitizedText,
		Provenance:    brain.ProvenanceLocalWorkspace,
		AuthorityTier: authz.TierName1Architecture,
		Metadata:      meta,
	})
	if err != nil {
		return "", false
	}
	return node.ID, true
}

func truncateStr(s string, max int) string {
	clean := strings.Join(strings.Fields(s), " ")
	runes := []rune(clean)
	if len(runes) <= max {
		return clean
	}
	return string(runes[:max-3]) + "..."
}
