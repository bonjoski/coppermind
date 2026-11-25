package explorer

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/bonjoski/coppermind/pkg/authz"
	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/storage"
)

// TUI provides a lightweight, zero-dependency interactive terminal Brain Explorer
// across Search (with ScoreBreakdown), Graph, Timeline, Lineage, Proposals, Inbox & Vault Health.
type TUI struct {
	mgr        *brain.Manager
	graphStore storage.GraphStore
	inboxStore storage.InboxStore
	vecStore   storage.VectorAdminStore
	expStore   storage.ExplorerStore
	in         io.Reader
	out        io.Writer
}

// NewTUI creates an interactive terminal Brain Explorer session.
func NewTUI(mgr *brain.Manager, in io.Reader, out io.Writer) *TUI {
	gStore, _ := mgr.Store().(storage.GraphStore)
	iStore, _ := mgr.Store().(storage.InboxStore)
	vStore, _ := mgr.Store().(storage.VectorAdminStore)
	eStore, _ := mgr.Store().(storage.ExplorerStore)
	return &TUI{
		mgr:        mgr,
		graphStore: gStore,
		inboxStore: iStore,
		vecStore:   vStore,
		expStore:   eStore,
		in:         in,
		out:        out,
	}
}

// Run starts the interactive command loop until EOF or 'q'.
func (t *TUI) Run(ctx context.Context) error {
	t.renderHeader(ctx)
	scanner := bufio.NewScanner(t.in)
	for {
		fmt.Fprint(t.out, "\ncoppermind-tui> ")
		if !scanner.Scan() {
			return scanner.Err()
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		cmd := strings.ToLower(parts[0])
		arg := strings.TrimSpace(strings.TrimPrefix(line, parts[0]))

		switch cmd {
		case "q", "quit", "exit":
			fmt.Fprintln(t.out, "Closing Coppermind TUI.")
			return nil
		case "h", "help", "?":
			t.renderHelp()
		case "1", "s", "search":
			if arg == "" {
				fmt.Fprintln(t.out, "Usage: search <query>")
				continue
			}
			t.renderSearch(ctx, arg)
		case "2", "g", "graph":
			if arg == "" {
				fmt.Fprintln(t.out, "Usage: graph <memory_id_or_file_path>")
				continue
			}
			t.renderGraph(ctx, arg)
		case "3", "i", "inbox", "obs":
			t.renderInboxAndObs(ctx)
		case "4", "health", "status":
			t.renderHealth(ctx)
		case "5", "t", "timeline":
			limit := 15
			if arg != "" {
				if n, err := strconv.Atoi(arg); err == nil && n > 0 && n <= 100 {
					limit = n
				}
			}
			t.renderTimeline(ctx, limit)
		case "lineage":
			if arg == "" {
				fmt.Fprintln(t.out, "Usage: lineage <memory_id>")
				continue
			}
			t.renderLineage(ctx, arg)
		case "proposals":
			t.renderProposals(ctx)
		case "scopes":
			t.renderScopes(ctx)
		case "delete", "rm":
			if arg == "" {
				fmt.Fprintln(t.out, "Usage: delete <memory_id>")
				continue
			}
			t.deleteMemory(ctx, arg)
		case "resolve":
			if arg == "" {
				fmt.Fprintln(t.out, "Usage: resolve <observation_id>")
				continue
			}
			if err := t.mgr.ResolveObservation(ctx, arg); err != nil {
				fmt.Fprintf(t.out, "Error: %v\n", err)
			} else {
				fmt.Fprintf(t.out, "✓ Resolved observation %s\n", arg)
			}
		case "approve":
			t.curateProposal(ctx, arg, string(authz.StatusActive), authz.TierName1Architecture)
		case "reject":
			t.curateProposal(ctx, arg, string(authz.StatusRejected), "")
		case "dismiss":
			if arg == "" || t.inboxStore == nil {
				fmt.Fprintln(t.out, "Usage: dismiss <ticket_id>")
				continue
			}
			if err := t.inboxStore.ResolvePendingTicket(ctx, arg, "dismissed"); err != nil {
				fmt.Fprintf(t.out, "Error: %v\n", err)
			} else {
				fmt.Fprintf(t.out, "✓ Dismissed inbox ticket %s\n", arg)
			}
		case "verify":
			if arg == "" {
				arg = "default"
			}
			ok, cnt, badID, err := t.mgr.VerifySessionChain(ctx, arg)
			if err != nil || !ok {
				fmt.Fprintf(t.out, "✗ Merkle verification FAILED for %q at %s: %v\n", arg, badID, err)
			} else {
				fmt.Fprintf(t.out, "✓ Merkle chain INTACT for session %q (%d verified nodes)\n", arg, cnt)
			}
		case "reindex":
			if t.vecStore == nil {
				fmt.Fprintln(t.out, "Reindex not supported by active storage backend.")
				continue
			}
			stats, err := t.vecStore.ReindexVectors(ctx, t.mgr.Embedder(), t.mgr.EmbedderModelName(), 128, false)
			if err != nil {
				fmt.Fprintf(t.out, "Reindex failed: %v\n", err)
			} else {
				fmt.Fprintf(t.out, "✓ Reindexed %d/%d nodes with %s in %s\n",
					stats.Reindexed, stats.TotalNodes, stats.ModelName, stats.Duration.Round(time.Millisecond))
			}
		default:
			t.renderSearch(ctx, line)
		}
	}
}

func (t *TUI) renderScopes(ctx context.Context) {
	if t.expStore == nil {
		fmt.Fprintln(t.out, "Scopes not supported by active storage backend.")
		return
	}
	scopes, err := t.expStore.ListScopes(ctx)
	if err != nil {
		fmt.Fprintf(t.out, "Error listing scopes: %v\n", err)
		return
	}
	if len(scopes) == 0 {
		fmt.Fprintln(t.out, "No active memories in vault.")
		return
	}
	fmt.Fprintln(t.out, "Hierarchical Scopes:")
	for _, s := range scopes {
		label := s.Scope
		if label == "" {
			label = "(vault-global)"
		}
		indent := strings.Repeat("  ", s.Depth)
		fmt.Fprintf(t.out, "%s- %s  (%d memories, %d TIER_0/1 invariants)\n", indent, label, s.MemoryCount, s.InvariantCount)
	}
}

func (t *TUI) curateProposal(ctx context.Context, id, newStatus, newTier string) {
	if id == "" {
		fmt.Fprintln(t.out, "Usage: approve|reject <proposal_id>")
		return
	}
	node, err := t.mgr.Store().GetByID(ctx, id)
	if err != nil || node == nil {
		fmt.Fprintf(t.out, "Proposal %q not found\n", id)
		return
	}
	node.LifecycleStatus = newStatus
	if newTier != "" {
		node.AuthorityTier = newTier
	}
	node.UpdatedAt = time.Now()
	if err := t.mgr.Store().Store(ctx, node); err != nil {
		fmt.Fprintf(t.out, "Error updating proposal: %v\n", err)
		return
	}
	fmt.Fprintf(t.out, "✓ Updated %s -> lifecycle=%s tier=%s\n", id, node.LifecycleStatus, node.AuthorityTier)
}

func (t *TUI) renderHeader(ctx context.Context) {
	cnt, _ := t.mgr.Count(ctx, "")
	fmt.Fprintf(t.out, "╔══════════════════════════════════════════════════════════════════╗\n")
	fmt.Fprintf(t.out, "║  🧠 Coppermind Memory Explorer TUI (%4d memories | %s)\n", cnt, t.mgr.EmbedderModelName())
	fmt.Fprintf(t.out, "║  [1] search  [2] graph  [3] inbox  [4] health  [5] timeline  [q] quit\n")
	fmt.Fprintf(t.out, "╚══════════════════════════════════════════════════════════════════╝\n")
}

func (t *TUI) renderHelp() {
	fmt.Fprintln(t.out, "Commands:")
	fmt.Fprintln(t.out, "  search <query>         Hybrid + 1-hop graph recall with ScoreBreakdown")
	fmt.Fprintln(t.out, "  graph <id|file>        Inspect 1-2 hop graph edges or file impact")
	fmt.Fprintln(t.out, "  timeline [limit]       Chronological episodic timeline of memories")
	fmt.Fprintln(t.out, "  lineage <memory_id>    Walk supersession ancestors and audit rationale")
	fmt.Fprintln(t.out, "  proposals              List PROPOSED learnings awaiting approval")
	fmt.Fprintln(t.out, "  inbox                  Show open observations, PROPOSED learnings & pending tickets")
	fmt.Fprintln(t.out, "  resolve <obs_id>       Mark a memory lens observation resolved")
	fmt.Fprintln(t.out, "  approve <proposal_id>  Promote a PROPOSED learning to TIER_1_ARCHITECTURE")
	fmt.Fprintln(t.out, "  reject <proposal_id>   Reject a PROPOSED learning")
	fmt.Fprintln(t.out, "  delete <memory_id>     Delete a noisy chunk (refuses TIER_0_SOVEREIGN fail-closed)")
	fmt.Fprintln(t.out, "  dismiss <ticket_id>    Dismiss a pending commit inbox ticket")
	fmt.Fprintln(t.out, "  verify [session]       Audit cryptographic Merkle chain for a session")
	fmt.Fprintln(t.out, "  reindex                Re-embed mismatched nodes with active embedder")
	fmt.Fprintln(t.out, "  health                 Show vector model coverage & vault stats")
	fmt.Fprintln(t.out, "  q                      Exit TUI")
}

func (t *TUI) renderTimeline(ctx context.Context, limit int) {
	if t.expStore == nil {
		fmt.Fprintln(t.out, "Timeline not supported by active storage backend.")
		return
	}
	nodes, err := t.expStore.ListTimeline(ctx, storage.TimelineFilter{Limit: limit})
	if err != nil {
		fmt.Fprintf(t.out, "Timeline error: %v\n", err)
		return
	}
	fmt.Fprintf(t.out, "Episodic Timeline (latest %d):\n", limit)
	if len(nodes) == 0 {
		fmt.Fprintln(t.out, "  (empty)")
		return
	}
	for i, n := range nodes {
		ts := n.CreatedAt.UTC().Format("2006-01-02 15:04")
		status := n.LifecycleStatus
		if status == "" {
			status = "ACTIVE"
		}
		fmt.Fprintf(t.out, "  %2d. [%s] %s [%s | %s | %s] %s\n", i+1, ts, n.ID, status, n.AuthorityTier, n.Category, truncateTUI(n.Content, 85))
	}
}

func (t *TUI) renderLineage(ctx context.Context, id string) {
	if t.expStore == nil {
		fmt.Fprintln(t.out, "Lineage inspection not supported by active storage backend.")
		return
	}
	ancestors, audit, err := t.expStore.GetLineage(ctx, id)
	if err != nil || len(ancestors) == 0 {
		fmt.Fprintf(t.out, "No lineage found for %q\n", id)
		return
	}
	fmt.Fprintf(t.out, "Supersession Lineage for %s (%d nodes):\n", id, len(ancestors))
	for i, a := range ancestors {
		prefix := "●"
		if i > 0 {
			prefix = "↳"
		}
		fmt.Fprintf(t.out, "  %s %s [%s | %s] %s\n", prefix, a.ID, a.LifecycleStatus, a.AuthorityTier, truncateTUI(a.Content, 88))
	}
	if len(audit) > 0 {
		fmt.Fprintf(t.out, "Audit Trail (%d events):\n", len(audit))
		for _, ev := range audit {
			fmt.Fprintf(t.out, "  • %s superseded %s (%s)\n", ev.SupersedingID, ev.SupersededID, ev.Rationale)
		}
	}
}

func (t *TUI) renderProposals(ctx context.Context) {
	if t.expStore == nil {
		fmt.Fprintln(t.out, "Proposals not supported by active storage backend.")
		return
	}
	nodes, err := t.expStore.ListProposals(ctx, 25)
	if err != nil {
		fmt.Fprintf(t.out, "Proposals error: %v\n", err)
		return
	}
	fmt.Fprintln(t.out, "PROPOSED Learnings:")
	if len(nodes) == 0 {
		fmt.Fprintln(t.out, "  (none pending)")
		return
	}
	for _, n := range nodes {
		fmt.Fprintf(t.out, "  • %s [%s | %s] %s\n", n.ID, n.AuthorityTier, n.Category, truncateTUI(n.Content, 90))
	}
}

func (t *TUI) deleteMemory(ctx context.Context, id string) {
	node, err := t.mgr.Store().GetByID(ctx, id)
	if err != nil || node == nil {
		fmt.Fprintf(t.out, "Memory %q not found\n", id)
		return
	}
	if node.AuthorityTier == authz.TierName0Sovereign {
		fmt.Fprintf(t.out, "✗ Refused fail-closed: TIER_0_SOVEREIGN memory %s cannot be deleted via TUI (use supersession)\n", id)
		return
	}
	if err := t.mgr.Store().Delete(ctx, id); err != nil {
		fmt.Fprintf(t.out, "Error deleting %s: %v\n", id, err)
		return
	}
	fmt.Fprintf(t.out, "✓ Deleted memory %s\n", id)
}

func (t *TUI) renderSearch(ctx context.Context, query string) {
	res, err := t.mgr.Recall(ctx, brain.RecallRequest{
		Query:   query,
		Hybrid:  true,
		Hops:    1,
		Limit:   6,
		Explain: true,
	})
	if err != nil {
		fmt.Fprintf(t.out, "Search error: %v\n", err)
		return
	}
	if len(res) == 0 {
		fmt.Fprintln(t.out, "No matches found.")
		return
	}
	for i, r := range res {
		snippet := strings.Join(strings.Fields(r.Node.Content), " ")
		if len(snippet) > 120 {
			snippet = snippet[:117] + "..."
		}
		fmt.Fprintf(t.out, "%d. [%.3f] %s [%s | %s]\n   %s\n",
			i+1, r.Score, r.Node.ID, r.Node.AuthorityTier, r.Node.Category, snippet)
		if r.Breakdown != nil {
			fmt.Fprintf(t.out, "   └─ explain: hybrid=%.2f actr=%.2f repo=%.2f graph=%.2f tier=%.2f\n",
				r.Breakdown.HybridScore, r.Breakdown.RecencyACTR, r.Breakdown.RepoAffinity, r.Breakdown.GraphBoost, r.Breakdown.TierWeight)
		}
	}
}

func (t *TUI) renderGraph(ctx context.Context, target string) {
	if t.graphStore == nil {
		fmt.Fprintln(t.out, "Graph inspection not supported by active storage backend.")
		return
	}
	if strings.Contains(target, "/") || strings.Contains(target, ".") {
		nodes, err := t.graphStore.ImpactForFile(ctx, target, 10)
		if err != nil {
			fmt.Fprintf(t.out, "Impact error: %v\n", err)
			return
		}
		fmt.Fprintf(t.out, "File Impact for %s (%d nodes):\n", target, len(nodes))
		for _, n := range nodes {
			fmt.Fprintf(t.out, "  • %s [%s | %s] %s\n", n.ID, n.AuthorityTier, n.Category, truncateTUI(n.Content, 90))
		}
		return
	}
	edges, err := t.graphStore.GetEdgesForNode(ctx, target)
	if err != nil {
		fmt.Fprintf(t.out, "Graph error: %v\n", err)
		return
	}
	fmt.Fprintf(t.out, "Edges for %s (%d):\n", target, len(edges))
	for _, e := range edges {
		dest := e.TargetID
		if dest == "" {
			dest = e.TargetEntity
		}
		fmt.Fprintf(t.out, "  • %s --[%s]--> %s (w=%.2f)\n", e.SourceID, e.Relation, dest, e.Weight)
	}
}

func (t *TUI) renderInboxAndObs(ctx context.Context) {
	obs, _ := t.mgr.ListObservations(ctx, "", "", "open", "high", 10)
	fmt.Fprintf(t.out, "Open High/Critical Observations (%d):\n", len(obs))
	for _, o := range obs {
		fmt.Fprintf(t.out, "  • %s [%s/%s] %s\n", o.ID, strings.ToUpper(o.Severity), o.SourceLens, truncateTUI(o.Content, 95))
	}
	if t.inboxStore != nil {
		tkts, _ := t.inboxStore.ListPendingTickets(ctx, "", "pending", 10)
		fmt.Fprintf(t.out, "Pending Zero-Key Lens Inbox (%d):\n", len(tkts))
		for _, tk := range tkts {
			fmt.Fprintf(t.out, "  • %s [%s] %s\n", tk.ID, tk.LensName, truncateTUI(tk.Summary, 95))
		}
	}
}

func (t *TUI) renderHealth(ctx context.Context) {
	cnt, _ := t.mgr.Count(ctx, "")
	fmt.Fprintf(t.out, "Active Embedder: %s (dim=%d)\nTotal Memories:  %d\n",
		t.mgr.EmbedderModelName(), t.mgr.Embedder().Dimension(), cnt)
	if t.vecStore != nil {
		if cov, err := t.vecStore.GetVectorCoverage(ctx, t.mgr.EmbedderModelName()); err == nil {
			fmt.Fprintf(t.out, "Vector Coverage: %d/%d matching active model\n", cov.MatchingNodes, cov.TotalNodes)
			for m, c := range cov.ByModel {
				fmt.Fprintf(t.out, "  • %-24s %d nodes\n", m, c)
			}
		}
	}
}

func truncateTUI(s string, max int) string {
	clean := strings.Join(strings.Fields(s), " ")
	runes := []rune(clean)
	if len(runes) <= max {
		return clean
	}
	return string(runes[:max-3]) + "..."
}
