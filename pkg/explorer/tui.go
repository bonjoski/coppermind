package explorer

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/storage/sqlite"
)

// TUI provides a lightweight, zero-dependency interactive terminal Brain Explorer
// across 4 tabs: Search (with ScoreBreakdown), Graph, Inbox & Observations, and Vault Health.
type TUI struct {
	mgr   *brain.Manager
	store *sqlite.SQLiteStore
	in    io.Reader
	out   io.Writer
}

// NewTUI creates an interactive terminal Brain Explorer session.
func NewTUI(mgr *brain.Manager, in io.Reader, out io.Writer) *TUI {
	sqlStore, _ := mgr.Store().(*sqlite.SQLiteStore)
	return &TUI{mgr: mgr, store: sqlStore, in: in, out: out}
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
		default:
			// Treat bare text as an instant search query for zero-friction exploration
			t.renderSearch(ctx, line)
		}
	}
}

func (t *TUI) renderHeader(ctx context.Context) {
	cnt, _ := t.mgr.Count(ctx, "")
	fmt.Fprintf(t.out, "╔══════════════════════════════════════════════════════════════╗\n")
	fmt.Fprintf(t.out, "║  🧠 Coppermind Brain Explorer TUI (%4d memories | %s)\n", cnt, t.mgr.EmbedderModelName())
	fmt.Fprintf(t.out, "║  Tabs: [1] search <q>  [2] graph <id|file>  [3] inbox  [4] health  [q] quit\n")
	fmt.Fprintf(t.out, "╚══════════════════════════════════════════════════════════════╝\n")
}

func (t *TUI) renderHelp() {
	fmt.Fprintln(t.out, "Commands:")
	fmt.Fprintln(t.out, "  search <query>       Hybrid + 1-hop graph recall with ScoreBreakdown")
	fmt.Fprintln(t.out, "  graph <id|file>      Inspect 1-2 hop graph edges or file impact")
	fmt.Fprintln(t.out, "  inbox                Show open high/crit observations & pending commit tickets")
	fmt.Fprintln(t.out, "  resolve <obs_id>     Mark a cognitive lens observation resolved")
	fmt.Fprintln(t.out, "  health               Show vector model coverage & vault stats")
	fmt.Fprintln(t.out, "  q                    Exit TUI")
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
	if t.store == nil {
		fmt.Fprintln(t.out, "Graph inspection requires SQLite backend.")
		return
	}
	if strings.Contains(target, "/") || strings.Contains(target, ".") {
		nodes, err := t.store.ImpactForFile(ctx, target, 10)
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
	edges, err := t.store.GetEdgesForNode(ctx, target)
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
	if t.store != nil {
		tkts, _ := t.store.ListPendingTickets(ctx, "", "pending", 10)
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
	if t.store != nil {
		if cov, err := t.store.GetVectorCoverage(ctx, t.mgr.EmbedderModelName()); err == nil {
			fmt.Fprintf(t.out, "Vector Coverage: %d/%d matching active model\n", cov.MatchingNodes, cov.TotalNodes)
			for m, c := range cov.ByModel {
				fmt.Fprintf(t.out, "  • %-24s %d nodes\n", m, c)
			}
		}
	}
}

func truncateTUI(s string, max int) string {
	clean := strings.Join(strings.Fields(s), " ")
	if len(clean) <= max {
		return clean
	}
	return clean[:max-3] + "..."
}
