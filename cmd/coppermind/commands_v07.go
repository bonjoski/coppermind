package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/brief"
	"github.com/bonjoski/coppermind/pkg/capsule"
	"github.com/bonjoski/coppermind/pkg/embedding"
	"github.com/bonjoski/coppermind/pkg/explorer"
	"github.com/bonjoski/coppermind/pkg/hook"
	"github.com/bonjoski/coppermind/pkg/lenses"
	"github.com/bonjoski/coppermind/pkg/storage/sqlite"
)

func runModels(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: coppermind models <list|pull> [arguments]")
		os.Exit(1)
	}
	action := args[0]
	switch action {
	case "list", "ls":
		fs := flag.NewFlagSet("models list", flag.ExitOnError)
		dataDir := fs.String("data-dir", "", "Data directory")
		project := fs.String("project", "", "Project vault")
		_ = fs.Parse(args[1:])

		mgr, activeProj, err := initManager(*dataDir, *project)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		defer mgr.Close()

		fmt.Printf("Active Embedder: %s (dim=%d)\nDefault Pack Path: %s\n\nAvailable Static Packs:\n",
			mgr.EmbedderModelName(), mgr.Embedder().Dimension(), embedding.DefaultStaticModelPath())
		for _, m := range embedding.KnownModels {
			fmt.Printf("  • %-18s (dim=%d) — %s\n", m.Alias, m.Dimension, m.Description)
		}
		if sqlStore, ok := mgr.Store().(*sqlite.SQLiteStore); ok {
			if cov, err := sqlStore.GetVectorCoverage(context.Background(), mgr.EmbedderModelName()); err == nil {
				fmt.Printf("\nVault %q Vector Coverage: %d/%d matching active model\n", activeProj, cov.MatchingNodes, cov.TotalNodes)
				for model, cnt := range cov.ByModel {
					fmt.Printf("  • %-24s %d nodes\n", model, cnt)
				}
			}
		}

	case "pull":
		fs := flag.NewFlagSet("models pull", flag.ExitOnError)
		outPath := fs.String("out", embedding.DefaultStaticModelPath(), "Destination CMVEC1 pack path")
		fromFile := fs.String("from-file", "", "Install from a verified local .cmvec file")
		url := fs.String("url", "", "Remote HTTPS URL for a CMVEC1 pack (requires --sha256)")
		shaPin := fs.String("sha256", "", "Expected SHA-256 hex digest pin")
		_ = fs.Parse(args[1:])

		alias := "sovereign-dev-256"
		if fs.NArg() > 0 {
			alias = fs.Arg(0)
		}

		emb, sum, err := embedding.InstallStaticModel(context.Background(), alias, *outPath, *fromFile, *url, *shaPin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error installing static model: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ Installed verified CMVEC1 static embedder %q\n  • Path:   %s\n  • Dim:    %d (vocab=%d)\n  • SHA256: %s\n  • Next:   coppermind reindex-vectors\n",
			emb.ModelName(), *outPath, emb.Dimension(), emb.VocabSize(), sum)

	default:
		fmt.Fprintf(os.Stderr, "Unknown models action %q (expected list or pull)\n", action)
		os.Exit(1)
	}
}

func runReindexVectors(args []string) {
	fs := flag.NewFlagSet("reindex-vectors", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "Data directory")
	project := fs.String("project", "", "Project vault")
	batchSize := fs.Int("batch-size", 128, "Write transaction micro-batch size")
	dryRun := fs.Bool("dry-run", false, "Report how many nodes need re-embedding without writing")
	_ = fs.Parse(args)

	mgr, activeProj, err := initManager(*dataDir, *project)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer mgr.Close()

	sqlStore, ok := mgr.Store().(*sqlite.SQLiteStore)
	if !ok {
		fmt.Fprintln(os.Stderr, "Error: reindex-vectors is currently supported on SQLite Profile A vaults")
		os.Exit(1)
	}

	stats, err := sqlStore.ReindexVectors(context.Background(), mgr.Embedder(), mgr.EmbedderModelName(), *batchSize, *dryRun)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reindexing vectors: %v\n", err)
		os.Exit(1)
	}
	mode := "Reindexed"
	if *dryRun {
		mode = "Would reindex (dry-run)"
	}
	fmt.Printf("✓ %s vault %q with %s (dim=%d) in %s\n  • Total:     %d\n  • Updated:   %d\n  • Unchanged: %d\n",
		mode, activeProj, stats.ModelName, stats.Dimension, stats.Duration.Round(time.Millisecond),
		stats.TotalNodes, stats.Reindexed, stats.Skipped)
}

func runGraph(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: coppermind graph <neighbors <mem_id> | impact <file_path>>")
		os.Exit(1)
	}
	action := args[0]
	fs := flag.NewFlagSet("graph "+action, flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "Data directory")
	project := fs.String("project", "", "Project vault")
	hops := fs.Int("hops", 1, "Graph traversal hops (1 or 2)")
	limit := fs.Int("limit", 15, "Max results")
	_ = fs.Parse(args[1:])

	if fs.NArg() == 0 {
		fmt.Fprintf(os.Stderr, "Error: target argument required for 'graph %s'\n", action)
		os.Exit(1)
	}
	target := fs.Arg(0)

	mgr, _, err := initManager(*dataDir, *project)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer mgr.Close()

	sqlStore, ok := mgr.Store().(*sqlite.SQLiteStore)
	if !ok {
		fmt.Fprintln(os.Stderr, "Error: graph inspection requires SQLite backend")
		os.Exit(1)
	}

	switch action {
	case "impact":
		nodes, err := sqlStore.ImpactForFile(context.Background(), target, *limit)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Graph Impact for %q (%d linked nodes):\n", target, len(nodes))
		for i, n := range nodes {
			snippet := strings.Join(strings.Fields(n.Content), " ")
			if len(snippet) > 140 {
				snippet = snippet[:137] + "..."
			}
			fmt.Printf("%d. %s [%s | %s] %s\n", i+1, n.ID, n.AuthorityTier, n.Category, snippet)
		}
	case "neighbors":
		edges, err := sqlStore.GetEdgesForNode(context.Background(), target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Direct Edges for %s (%d):\n", target, len(edges))
		for _, e := range edges {
			dest := e.TargetID
			if dest == "" {
				dest = e.TargetEntity
			}
			fmt.Printf("  • %s --[%s]--> %s (w=%.2f)\n", e.SourceID, e.Relation, dest, e.Weight)
		}
		neighbors, _ := sqlStore.ExpandGraphNeighbors(context.Background(), []string{target}, *hops, brain.MemoryFilter{Limit: *limit})
		if len(neighbors) > 0 {
			fmt.Printf("\nExpanded Neighbors (hops=%d, %d nodes):\n", *hops, len(neighbors))
			for i, r := range neighbors {
				snippet := strings.Join(strings.Fields(r.Node.Content), " ")
				if len(snippet) > 120 {
					snippet = snippet[:117] + "..."
				}
				fmt.Printf("%d. %s [%s] via %v: %s\n", i+1, r.Node.ID, r.Node.AuthorityTier, r.GraphLinks, snippet)
			}
		}
	default:
		fmt.Fprintf(os.Stderr, "Unknown graph action %q (expected neighbors or impact)\n", action)
		os.Exit(1)
	}
}

func runBrief(args []string) {
	fs := flag.NewFlagSet("brief", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "Data directory")
	project := fs.String("project", "", "Project vault")
	repoDir := fs.String("repo", "", "Repository directory (defaults to cwd)")
	maxTokens := fs.Int("max-tokens", brief.HardMaxTokens, "Token budget ceiling (max 800)")
	format := fs.String("format", "markdown", "Output format: markdown or json")
	_ = fs.Parse(args)

	mgr, _, err := initManager(*dataDir, *project)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer mgr.Close()

	res, err := brief.Compile(context.Background(), mgr, brief.BriefRequest{
		RepoDir:   *repoDir,
		MaxTokens: *maxTokens,
		Format:    *format,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error compiling brief: %v\n", err)
		os.Exit(1)
	}
	if strings.EqualFold(*format, "json") {
		out, _ := res.MarshalJSONOutput()
		fmt.Println(out)
		return
	}
	fmt.Println(res.Markdown)
}

func runInbox(args []string) {
	action := "list"
	var rest []string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		action = args[0]
		rest = args[1:]
	} else {
		rest = args
	}

	fs := flag.NewFlagSet("inbox "+action, flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "Data directory")
	project := fs.String("project", "", "Project vault")
	lensName := fs.String("lens", "", "Filter by lens name")
	status := fs.String("status", "pending", "Ticket status filter (pending|completed|dismissed)")
	limit := fs.Int("limit", 25, "Max tickets")
	_ = fs.Parse(rest)

	mgr, _, err := initManager(*dataDir, *project)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer mgr.Close()

	sqlStore, ok := mgr.Store().(*sqlite.SQLiteStore)
	if !ok {
		fmt.Fprintln(os.Stderr, "Error: inbox requires SQLite backend")
		os.Exit(1)
	}

	switch action {
	case "list", "ls":
		tickets, err := sqlStore.ListPendingTickets(context.Background(), *lensName, *status, *limit)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error listing inbox: %v\n", err)
			os.Exit(1)
		}
		if len(tickets) == 0 {
			fmt.Printf("No %s tickets in Pending Lens Inbox.\n", *status)
			return
		}
		fmt.Printf("Pending Lens Review Inbox (%d %s):\n", len(tickets), *status)
		for i, t := range tickets {
			fmt.Printf("%d. %s [%s | %s] %s (mem=%s)\n", i+1, t.ID, t.LensName, t.BranchName, t.Summary, t.MemoryID)
		}
	case "dismiss":
		if fs.NArg() == 0 {
			fmt.Fprintln(os.Stderr, "Usage: coppermind inbox dismiss <ticket_id>")
			os.Exit(1)
		}
		if err := sqlStore.ResolvePendingTicket(context.Background(), fs.Arg(0), "dismissed"); err != nil {
			fmt.Fprintf(os.Stderr, "Error dismissing ticket: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ Dismissed inbox ticket %s\n", fs.Arg(0))
	default:
		fmt.Fprintf(os.Stderr, "Unknown inbox action %q (expected list or dismiss)\n", action)
		os.Exit(1)
	}
}

func runHookIngestCommit(repoRoot string, dataDir, project string, jsonOut bool) {
	mgr, _, err := initManager(dataDir, project)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer mgr.Close()

	res, err := hook.IngestCommit(context.Background(), mgr, repoRoot, lenses.DefaultConfig())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Commit ingestion rejected: %v\n", err)
		os.Exit(1)
	}
	if jsonOut {
		b, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(b))
		return
	}
	fmt.Printf("✓ Ingested commit %.8s (%s/%s) -> %s (queued %d pending lens tickets)\n",
		res.CommitSHA, res.RepoName, res.BranchName, res.MemoryID, res.TicketsQueued)
}

func runCapsuleCartridgePack(args []string) {
	fs := flag.NewFlagSet("capsule pack-memories", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "Data directory")
	project := fs.String("project", "", "Project vault")
	outPath := fs.String("out", "knowledge.capsule", "Output cartridge path")
	name := fs.String("name", "", "Cartridge name")
	repo := fs.String("repo", "", "Filter by git_repo metadata")
	category := fs.String("category", "", "Filter by category")
	tier := fs.String("tier", "", "Filter by authority_tier")
	since := fs.String("since", "", "Filter created since (e.g. 30d or YYYY-MM-DD)")
	keySpec := fs.String("key", "", "Optional Ed25519 private key file or hex for signing")
	_ = fs.Parse(args)

	mgr, _, err := initManager(*dataDir, *project)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer mgr.Close()

	sqlStore, ok := mgr.Store().(*sqlite.SQLiteStore)
	if !ok {
		fmt.Fprintln(os.Stderr, "Error: pack-memories requires SQLite backend")
		os.Exit(1)
	}

	opts := capsule.CartridgeExportOptions{
		Name:     *name,
		Repo:     *repo,
		Category: *category,
		Tier:     *tier,
	}
	if strings.TrimSpace(*since) != "" {
		t, pErr := brain.ParseTemporalBound(*since, time.Now().UTC())
		if pErr != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", pErr)
			os.Exit(1)
		}
		opts.Since = &t
	}
	if strings.TrimSpace(*keySpec) != "" {
		priv, kErr := capsule.LoadEd25519PrivateKey(*keySpec)
		if kErr != nil {
			fmt.Fprintf(os.Stderr, "Error loading private key: %v\n", kErr)
			os.Exit(1)
		}
		opts.PrivateKey = priv
	}

	manifest, err := capsule.ExportCartridge(context.Background(), sqlStore, *outPath, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error exporting cartridge: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✓ Exported mergeable cartridge %q to %s\n  • Records: %d | Edges: %d | Signed: %t\n  • Merkle:  %s\n",
		manifest.Name, *outPath, manifest.RecordCount, manifest.EdgeCount, manifest.Signature != "", manifest.MerkleRoot)
}

func runCapsuleCartridgeMerge(args []string) {
	fs := flag.NewFlagSet("capsule merge", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "Data directory")
	project := fs.String("project", "", "Project vault")
	pubKeySpec := fs.String("pubkey", "", "Ed25519 public key file or hex")
	allowUnsigned := fs.Bool("allow-unsigned", false, "Allow merging an unsigned local cartridge (capped at TIER_2_MENTOR_CAPSULE / PROPOSED)")
	_ = fs.Parse(args)

	if fs.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "Usage: coppermind capsule merge [--pubkey <key>] [--allow-unsigned] <file.capsule>")
		os.Exit(1)
	}
	inPath := fs.Arg(0)

	mgr, activeProj, err := initManager(*dataDir, *project)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer mgr.Close()

	var pub ed25519.PublicKey
	if strings.TrimSpace(*pubKeySpec) != "" {
		p, pErr := capsule.LoadEd25519PublicKey(*pubKeySpec)
		if pErr != nil {
			fmt.Fprintf(os.Stderr, "Error loading public key: %v\n", pErr)
			os.Exit(1)
		}
		pub = p
	}

	res, err := capsule.MergeCartridge(context.Background(), mgr, inPath, capsule.CartridgeMergeOptions{
		RequiredPubKey: pub,
		AllowUnsigned:  *allowUnsigned,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cartridge merge rejected: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✓ Merged cartridge %q into vault %q (signed=%t)\n  • Imported: %d | Deduplicated: %d | Quarantined: %d | Edges: %d\n",
		res.Manifest.Name, activeProj, res.SignedVerified, res.ImportedCount, res.DeduplicatedSkip, res.QuarantinedSkip, res.EdgesRestored)
}

func runTUI(args []string) {
	fs := flag.NewFlagSet("tui", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "Data directory")
	project := fs.String("project", "", "Project vault")
	_ = fs.Parse(args)

	mgr, _, err := initManager(*dataDir, *project)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer mgr.Close()

	tui := explorer.NewTUI(mgr, os.Stdin, os.Stdout)
	if err := tui.Run(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "TUI exited with error: %v\n", err)
		os.Exit(1)
	}
}

func runUI(args []string) {
	fs := flag.NewFlagSet("ui", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "Data directory")
	project := fs.String("project", "", "Project vault")
	listen := fs.String("listen", "127.0.0.1:0", "Strict loopback address (127.0.0.1 only)")
	allowCurate := fs.Bool("allow-curate", false, "Enable authenticated POST curation endpoints (resolve/approve)")
	_ = fs.Parse(args)

	mgr, _, err := initManager(*dataDir, *project)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer mgr.Close()

	ws, err := explorer.NewWebServer(mgr, explorer.WebOptions{
		ListenAddr:  *listen,
		AllowCurate: *allowCurate,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	url, err := ws.Start()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed starting local explorer: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "🧠 Coppermind Local Brain Explorer listening strictly on 127.0.0.1\n  • Open: %s\n  • Mode: read-only=%t (Ctrl+C to stop)\n",
		url, !*allowCurate)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = ws.Close(ctx)
}
