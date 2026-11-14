package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/capsule"
	"github.com/bonjoski/coppermind/pkg/daemon"
	"github.com/bonjoski/coppermind/pkg/doctor"
	"github.com/bonjoski/coppermind/pkg/embedding"
	"github.com/bonjoski/coppermind/pkg/hook"
	"github.com/bonjoski/coppermind/pkg/indexer"
	"github.com/bonjoski/coppermind/pkg/keystore"
	"github.com/bonjoski/coppermind/pkg/mcp"
	"github.com/bonjoski/coppermind/pkg/project"
	"github.com/bonjoski/coppermind/pkg/queue"
	"github.com/bonjoski/coppermind/pkg/router"
	"github.com/bonjoski/coppermind/pkg/scratchpad"
	"github.com/bonjoski/coppermind/pkg/seeder"
	"github.com/bonjoski/coppermind/pkg/storage/postgres"
	"github.com/bonjoski/coppermind/pkg/storage/sqlite"
	"github.com/bonjoski/coppermind/pkg/version"
	"github.com/bonjoski/coppermind/pkg/worker"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	args := os.Args[1:]
	for len(args) > 0 {
		if (args[0] == "--project" || args[0] == "-p") && len(args) > 1 {
			_ = os.Setenv("COPPERMIND_PROJECT", args[1])
			args = args[2:]
		} else if strings.HasPrefix(args[0], "--project=") {
			_ = os.Setenv("COPPERMIND_PROJECT", strings.TrimPrefix(args[0], "--project="))
			args = args[1:]
		} else if strings.HasPrefix(args[0], "-p=") {
			_ = os.Setenv("COPPERMIND_PROJECT", strings.TrimPrefix(args[0], "-p="))
			args = args[1:]
		} else if (args[0] == "--data-dir") && len(args) > 1 {
			_ = os.Setenv("COPPERMIND_DATA_DIR", args[1])
			args = args[2:]
		} else if strings.HasPrefix(args[0], "--data-dir=") {
			_ = os.Setenv("COPPERMIND_DATA_DIR", strings.TrimPrefix(args[0], "--data-dir="))
			args = args[1:]
		} else if (args[0] == "--profile" || args[0] == "-profile") && len(args) > 1 {
			_ = os.Setenv("COPPERMIND_PROFILE", args[1])
			args = args[2:]
		} else if strings.HasPrefix(args[0], "--profile=") {
			_ = os.Setenv("COPPERMIND_PROFILE", strings.TrimPrefix(args[0], "--profile="))
			args = args[1:]
		} else if strings.HasPrefix(args[0], "-profile=") {
			_ = os.Setenv("COPPERMIND_PROFILE", strings.TrimPrefix(args[0], "-profile="))
			args = args[1:]
		} else {
			break
		}
	}

	if len(args) == 0 {
		printUsage()
		os.Exit(1)
	}

	command := args[0]
	cmdArgs := args[1:]
	switch command {
	case "mcp":
		runMCP(cmdArgs)
	case "daemon":
		runDaemon(cmdArgs)
	case "remember":
		runRemember(cmdArgs)
	case "recall":
		runRecall(cmdArgs)
	case "scratchpad":
		runScratchpad(cmdArgs)
	case "dispatch":
		runDispatch(cmdArgs)
	case "seed":
		runSeed(cmdArgs)
	case "index":
		runIndex(cmdArgs)
	case "export":
		runExport(cmdArgs)
	case "import":
		runImport(cmdArgs)
	case "verify":
		runVerify(cmdArgs)
	case "vacuum", "gc":
		runVacuum(cmdArgs)
	case "project", "projects":
		runProject(cmdArgs)
	case "doctor":
		runDoctor(cmdArgs)
	case "hook":
		runHook(cmdArgs)
	case "status":
		runStatus(cmdArgs)
	case "version", "--version", "-v":
		fmt.Printf("coppermind version %s\n", version.String())
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %q\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`Coppermind — Portable Cognitive AI Brain & Agent Memory Runtime

Usage:
  coppermind <command> [arguments]

Commands:
  mcp          Start the Model Context Protocol (MCP) server over STDIO
  daemon       Start background daemon listening on Unix domain socket or TCP
  remember     Store an architectural fact, decision, or runbook into memory
  recall       Perform semantic or hybrid similarity search over stored memories
  scratchpad   Interact with fast in-memory working state (get, set, keys)
  dispatch     Enqueue an asynchronous cognitive task onto the message bus
  seed         Ingest markdown files or directories into memory
  index        Scan, chunk, and index a codebase repository into semantic memory
  export       Export the brain into a portable, verified capsule archive
  import       Restore a brain from a capsule archive with path traversal checks
  verify       Audit cryptographic Merkle chain integrity for a session
  vacuum       Purge expired TTL memories and compact SQLite storage
  project      Manage isolated vaults (list, use, create, delete)
  doctor       Execute the 10-pillar diagnostic inspection suite
  hook         Install automated git hooks (e.g. post-commit episodic capture)
  status       Display brain health metrics and stored memory counts
  version      Print version information

Flags for mcp/daemon:
  --data-dir   Directory for storing database files (default: ~/.coppermind)

Examples:
  coppermind mcp
  coppermind remember --category architecture "Use pure-Go SQLite WAL mode"
  coppermind recall "Which database mode do we use?"
  coppermind scratchpad set active_session "worktree_beta"
  coppermind status`)
}

func getDBPath(dataDir, explicitProject string) string {
	pm := project.NewManager(dataDir)
	_, dir, err := pm.ResolveProject(explicitProject)
	if err != nil {
		if dataDir == "" {
			home, _ := os.UserHomeDir()
			dataDir = filepath.Join(home, ".coppermind")
		}
		return filepath.Join(dataDir, "coppermind.db")
	}
	return filepath.Join(dir, "coppermind.db")
}

func getProfile() string {
	p := strings.ToLower(strings.TrimSpace(os.Getenv("COPPERMIND_PROFILE")))
	if p == "cluster" || p == "b" || p == "profile-b" || p == "profile_b" {
		return "cluster"
	}
	return "local"
}

func initManager(dataDir, explicitProject string) (*brain.Manager, string, error) {
	pm := project.NewManager(dataDir)
	projectName, projectDir, err := pm.ResolveProject(explicitProject)
	if err != nil {
		return nil, "", err
	}

	embedder := embedding.NewEmbedderFromEnv()
	profile := getProfile()

	if profile == "cluster" {
		pgURL := os.Getenv("COPPERMIND_POSTGRES_URL")
		if pgURL == "" {
			pgPort := os.Getenv("COPPERMIND_PG_PORT")
			if pgPort == "" {
				pgPort = "5433"
			}
			pgURL = fmt.Sprintf("postgres://coppermind:sovereign_secret@localhost:%s/coppermind?sslmode=disable", pgPort)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		store, err := postgres.NewPostgresStore(ctx, postgres.Config{
			URL:       pgURL,
			Dimension: embedder.Dimension(),
		})
		if err != nil {
			return nil, "", fmt.Errorf("failed to open cluster postgres store: %w", err)
		}

		redisAddr := os.Getenv("COPPERMIND_REDIS_ADDR")
		if redisAddr == "" {
			redisAddr = "127.0.0.1:6379"
		}
		sp := scratchpad.NewRedisScratchpad(redisAddr)
		return brain.NewManager(store, embedder, sp), projectName, nil
	}

	dbPath := filepath.Join(projectDir, "coppermind.db")
	store, err := sqlite.NewSQLiteStore(dbPath)
	if err != nil {
		return nil, "", fmt.Errorf("failed to open storage at %s: %w", dbPath, err)
	}

	sp := scratchpad.NewMemoryScratchpad()
	return brain.NewManager(store, embedder, sp), projectName, nil
}

func initBroker() (queue.Broker, error) {
	amqpURL := os.Getenv("COPPERMIND_RABBITMQ_URL")
	if amqpURL != "" || getProfile() == "cluster" {
		if amqpURL == "" {
			amqpURL = "amqp://guest:guest@localhost:5672/"
		}
		return queue.NewRabbitMQBroker(amqpURL, "coppermind.tasks")
	}
	return queue.NewEmbeddedBroker(256), nil
}

func initRouter() router.ModelRouter {
	endpoint := os.Getenv("COPPERMIND_LITELLM_URL")
	model := os.Getenv("COPPERMIND_MODEL")
	apiKey := os.Getenv("COPPERMIND_API_KEY")

	// If OpenAI / Gemini keys are in ambient environment
	if apiKey == "" {
		apiKey = os.Getenv("OPENAI_API_KEY")
	}
	if apiKey == "" {
		apiKey = os.Getenv("GEMINI_API_KEY")
		if apiKey != "" && endpoint == "" {
			endpoint = "https://generativelanguage.googleapis.com/v1beta/openai"
			if model == "" {
				model = "gemini-2.5-flash"
			}
		}
	}

	if endpoint == "" {
		endpoint = os.Getenv("OPENAI_BASE_URL")
	}

	if endpoint == "" && apiKey == "" {
		// Offline fallback reflection mode; does not query keystore or prompt Touch ID
		return router.NewLiteLLMRouter("", "")
	}

	if apiKey == "" {
		ks := keystore.NewLocksmithKeystore()
		apiKey, _ = ks.GetSecret(context.Background(), "OPENAI_API_KEY")
	}

	return router.NewLiteLLMRouterWithModel(endpoint, apiKey, model)
}

func runMCP(args []string) {
	fs := flag.NewFlagSet("mcp", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "Data directory for database files")
	project := fs.String("project", "", "Target project vault (e.g. github, personal, work)")
	_ = fs.Parse(args)

	mgr, activeProj, err := initManager(*dataDir, *project)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer mgr.Close()

	broker, err := initBroker()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to initialize RabbitMQ broker (%v), using embedded broker\n", err)
		broker = queue.NewEmbeddedBroker(256)
	}
	defer broker.Close()

	rtr := initRouter()
	cw := worker.NewCognitiveWorker(broker, mgr, rtr)
	ctx := context.Background()
	if err := cw.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to start cognitive worker: %v\n", err)
	}
	defer cw.Stop()

	server := mcp.NewServer(mgr, os.Stdout)
	server.SetWorker(broker, cw)
	_ = activeProj

	if err := server.ServeSTDIO(ctx, os.Stdin); err != nil {
		fmt.Fprintf(os.Stderr, "MCP server stopped: %v\n", err)
		os.Exit(1)
	}
}

func runRemember(args []string) {
	fs := flag.NewFlagSet("remember", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "Data directory")
	project := fs.String("project", "", "Target project vault (e.g. github, personal, work)")
	category := fs.String("category", "general", "Category (architecture, convention, decision, runbook)")
	session := fs.String("session", "default", "Session or worktree identifier")
	ttl := fs.Duration("ttl", 0, "Optional TTL (e.g. 24h, 30m) after which the memory expires")
	_ = fs.Parse(args)

	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintf(os.Stderr, "Error: content is required\nUsage: coppermind remember [--category <cat>] <content>\n")
		os.Exit(1)
	}
	content := strings.Join(rest, " ")

	mgr, activeProj, err := initManager(*dataDir, *project)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer mgr.Close()

	node, err := mgr.Remember(context.Background(), brain.RememberRequest{
		SessionID:  *session,
		Category:   *category,
		Content:    content,
		Provenance: brain.ProvenanceLocalWorkspace,
		TTL:        *ttl,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error storing memory: %v\n", err)
		os.Exit(1)
	}

	expMsg := ""
	if node.ExpiresAt != nil {
		expMsg = fmt.Sprintf(" (expires %s)", node.ExpiresAt.Format("2006-01-02 15:04"))
	}
	fmt.Printf("✓ Stored memory [%s] in vault %q [%s]%s: %s\n", node.ID, activeProj, node.Category, expMsg, node.Content)
}

func runRecall(args []string) {
	fs := flag.NewFlagSet("recall", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "Data directory")
	project := fs.String("project", "", "Target project vault (e.g. github, personal, work)")
	category := fs.String("category", "", "Optional category filter")
	session := fs.String("session", "", "Optional session filter")
	repo := fs.String("repo", "", "Optional git repository scope filter")
	branch := fs.String("branch", "", "Optional git branch scope filter")
	limit := fs.Int("limit", 5, "Maximum results to retrieve")
	minScore := fs.Float64("min-score", 0.0, "Minimum cosine score threshold")
	hybrid := fs.Bool("hybrid", true, "Use hybrid FTS5 BM25 + vector RRF search (default true)")
	_ = fs.Parse(args)

	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintf(os.Stderr, "Error: search query is required\nUsage: coppermind recall [--limit 5] <query>\n")
		os.Exit(1)
	}
	query := strings.Join(rest, " ")

	mgr, activeProj, err := initManager(*dataDir, *project)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer mgr.Close()

	results, err := mgr.Recall(context.Background(), brain.RecallRequest{
		SessionID: *session,
		Category:  *category,
		Query:     query,
		Limit:     *limit,
		MinScore:  float32(*minScore),
		Hybrid:    *hybrid,
		GitRepo:   *repo,
		GitBranch: *branch,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error recalling memory: %v\n", err)
		os.Exit(1)
	}

	if len(results) == 0 {
		fmt.Println("No matching memories found.")
		return
	}

	mode := "Hybrid BM25+Vector"
	if !*hybrid {
		mode = "Cosine Vector"
	}
	fmt.Printf("Found %d matching memories (%s) in vault %q for %q:\n\n", len(results), mode, activeProj, query)
	for i, r := range results {
		fmt.Printf("%d. [Score: %.3f] [%s | %s]\n   %s\n\n",
			i+1, r.Score, r.Node.Category, r.Node.SessionID, r.Node.Content)
	}
}

func runScratchpad(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: coppermind scratchpad <get|set|delete|keys> [key] [value]")
		os.Exit(1)
	}
	action := args[0]
	var sp brain.Scratchpad
	if getProfile() == "cluster" {
		redisAddr := os.Getenv("COPPERMIND_REDIS_ADDR")
		if redisAddr == "" {
			redisAddr = "127.0.0.1:6379"
		}
		sp = scratchpad.NewRedisScratchpad(redisAddr)
	} else {
		sp = scratchpad.NewMemoryScratchpad()
	}
	ctx := context.Background()

	switch action {
	case "keys":
		keys := sp.Keys(ctx)
		fmt.Printf("Active keys (%d): %s\n", len(keys), strings.Join(keys, ", "))
	case "get":
		if len(args) < 2 {
			fmt.Println("Usage: coppermind scratchpad get <key>")
			os.Exit(1)
		}
		val, ok := sp.Get(ctx, args[1])
		if !ok {
			fmt.Printf("Key %q not found\n", args[1])
		} else {
			fmt.Println(val)
		}
	case "set":
		if len(args) < 3 {
			fmt.Println("Usage: coppermind scratchpad set <key> <value>")
			os.Exit(1)
		}
		_ = sp.Set(ctx, args[1], args[2], 0)
		fmt.Printf("Set %q\n", args[1])
	default:
		fmt.Fprintf(os.Stderr, "Unknown scratchpad action: %q\n", action)
		os.Exit(1)
	}
}

func runDispatch(args []string) {
	fs := flag.NewFlagSet("dispatch", flag.ExitOnError)
	session := fs.String("session", "default", "Target session or worktree")
	dataDir := fs.String("data-dir", "", "Data directory")
	project := fs.String("project", "", "Target project vault")
	_ = fs.Parse(args)

	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintf(os.Stderr, "Error: task_type is required\nUsage: coppermind dispatch [--session <sess>] <summarize_session|deep_reflect|extract_decisions|defrag_memory|index_git_tree>\n")
		os.Exit(1)
	}
	taskType := queue.TaskType(rest[0])

	mgr, _, err := initManager(*dataDir, *project)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer mgr.Close()

	broker, err := initBroker()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing broker: %v\n", err)
		os.Exit(1)
	}
	defer broker.Close()

	rtr := initRouter()
	cw := worker.NewCognitiveWorker(broker, mgr, rtr)
	ctx := context.Background()
	if err := cw.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Error starting worker: %v\n", err)
		os.Exit(1)
	}
	defer cw.Stop()

	task := &queue.TaskEnvelope{
		SessionID: *session,
		Type:      taskType,
	}

	topic := fmt.Sprintf("tasks.%s", taskType)
	if err := broker.Publish(ctx, topic, task); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to publish task: %v\n", err)
		os.Exit(1)
	}

	// Give the local worker a moment to process the task synchronously if embedded
	time.Sleep(300 * time.Millisecond)
	fmt.Printf("✓ Successfully dispatched cognitive task [%s] (%s) for session %q\n", task.ID, task.Type, *session)
}

func runSeed(args []string) {
	fs := flag.NewFlagSet("seed", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "Data directory for database files")
	project := fs.String("project", "", "Target project vault")
	category := fs.String("category", "documentation", "Default category for ingested documents")
	_ = fs.Parse(args)

	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintf(os.Stderr, "Error: path to markdown file or directory is required\nUsage: coppermind seed [--category <cat>] <path>\n")
		os.Exit(1)
	}
	targetPath := rest[0]

	mgr, activeProj, err := initManager(*dataDir, *project)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer mgr.Close()

	ctx := context.Background()
	info, err := os.Stat(targetPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error accessing %s: %v\n", targetPath, err)
		os.Exit(1)
	}

	var count int
	if info.IsDir() {
		fmt.Printf("Seeding Coppermind vault %q from directory %s...\n", activeProj, targetPath)
		count, err = seeder.IngestDirectory(ctx, mgr, targetPath, *category)
	} else {
		fmt.Printf("Seeding Coppermind vault %q from file %s...\n", activeProj, targetPath)
		count, err = seeder.IngestFile(ctx, mgr, targetPath, *category)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Seeding failed: %v\n", err)
		os.Exit(1)
	}

	total, _ := mgr.Count(ctx, "")
	fmt.Printf("✓ Successfully ingested %d knowledge chunks into vault %q! (Total memories: %d)\n", count, activeProj, total)
}

func runIndex(args []string) {
	fs := flag.NewFlagSet("index", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "Data directory for database files")
	project := fs.String("project", "", "Target project vault")
	targetDir := fs.String("dir", ".", "Codebase directory to index")
	category := fs.String("category", "code", "Category for indexed code chunks")
	maxChunks := fs.Int("max-chunks", 1000, "Maximum chunks to index")
	chunkLines := fs.Int("chunk-lines", 50, "Lines per chunk")
	noProgress := fs.Bool("no-progress", false, "Disable progress meter")
	quiet := fs.Bool("quiet", false, "Suppress progress and status output")
	fs.BoolVar(quiet, "q", false, "Suppress progress and status output (alias)")
	_ = fs.Parse(args)

	mgr, activeProj, err := initManager(*dataDir, *project)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer mgr.Close()

	if !*quiet {
		fmt.Printf("🔍 Indexing codebase at %q into vault %q (category: %q)...\n", *targetDir, activeProj, *category)
	}

	meter := indexer.NewProgressMeter(indexer.MeterOptions{
		Writer:     os.Stdout,
		DisableTTY: *noProgress,
		Quiet:      *quiet,
	})
	defer meter.Close()

	stats, err := indexer.IndexDirectory(context.Background(), mgr, *targetDir, indexer.IndexOptions{
		Category:   *category,
		MaxChunks:  *maxChunks,
		ChunkLines: *chunkLines,
		OnProgress: meter.Update,
	})
	_ = meter.Close()

	if err != nil {
		fmt.Fprintf(os.Stderr, "Indexing failed: %v\n", err)
		os.Exit(1)
	}

	if !*quiet {
		fmt.Printf("✓ Codebase indexing complete in %v:\n", stats.Duration.Round(time.Millisecond))
		fmt.Printf("• Files Scanned: %d\n", stats.FilesScanned)
		fmt.Printf("• Files Indexed: %d (Chunks Stored: %d)\n", stats.FilesIndexed, stats.ChunksStored)
		fmt.Printf("• Files Skipped: %d\n", stats.FilesSkipped)
		if stats.Redactions > 0 {
			fmt.Printf("• Secret Redactions: %d (credentials quarantined)\n", stats.Redactions)
		}
	}
}

func runExport(args []string) {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "Data directory")
	project := fs.String("project", "", "Target project vault")
	outPath := fs.String("out", "coppermind.capsule", "Output capsule path")
	_ = fs.Parse(args)

	dbPath := getDBPath(*dataDir, *project)
	manifest, err := capsule.ExportCapsule(context.Background(), dbPath, *outPath, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Export failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Successfully exported brain capsule to %s\n", *outPath)
	fmt.Printf("• Total Records: %d\n", manifest.TotalRecords)
	fmt.Printf("• SHA-256 Checksum: %s\n", manifest.DBChecksum)
}

func runImport(args []string) {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "Data directory")
	project := fs.String("project", "", "Target project vault")
	_ = fs.Parse(args)

	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintf(os.Stderr, "Error: capsule path is required\nUsage: coppermind import <capsule.capsule>\n")
		os.Exit(1)
	}
	capsulePath := rest[0]
	targetDB := getDBPath(*dataDir, *project)

	manifest, err := capsule.ImportCapsule(context.Background(), capsulePath, targetDB, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Import failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Successfully restored brain capsule from %s\n", capsulePath)
	fmt.Printf("• Restored Records: %d\n", manifest.TotalRecords)
	fmt.Printf("• Verified Checksum: %s\n", manifest.DBChecksum)
}

func runVerify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "Data directory")
	project := fs.String("project", "", "Target project vault")
	session := fs.String("session", "", "Session ID to verify (empty for default)")
	_ = fs.Parse(args)

	mgr, activeProj, err := initManager(*dataDir, *project)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer mgr.Close()

	targetSession := *session
	if targetSession == "" {
		targetSession = "default"
	}

	fmt.Printf("🔍 Auditing cryptographic Merkle chain for session %q in vault %q...\n", targetSession, activeProj)
	intact, count, badID, err := mgr.VerifySessionChain(context.Background(), targetSession)
	if err != nil || !intact {
		fmt.Printf("❌ Cryptographic chain verification FAILED!\n• Tampered Node: %s\n• Error: %v\n", badID, err)
		os.Exit(1)
	}

	fmt.Printf("✓ Cryptographic Merkle chain verified INTACT!\n• Verified Nodes: %d\n• Tampering: None detected\n", count)
}

func runVacuum(args []string) {
	fs := flag.NewFlagSet("vacuum", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "Data directory")
	project := fs.String("project", "", "Target project vault")
	_ = fs.Parse(args)

	mgr, activeProj, err := initManager(*dataDir, *project)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer mgr.Close()

	fmt.Printf("🧹 Running Coppermind memory purge & WAL compaction for vault %q...\n", activeProj)
	purged, err := mgr.PurgeExpired(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning during expired memory purge: %v\n", err)
	} else if purged > 0 {
		fmt.Printf("• Purged %d expired memory nodes\n", purged)
	}

	if err := mgr.Vacuum(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "Error during vacuum: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✓ Database compaction and passive WAL checkpoint complete!")
}

func runDaemon(args []string) {
	fs := flag.NewFlagSet("daemon", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "Data directory")
	project := fs.String("project", "", "Target project vault")
	socketPath := fs.String("socket", "", "Unix Domain Socket path (default: ~/.coppermind/coppermind.sock)")
	tcpAddr := fs.String("listen", "", "Optional TCP listen address (e.g. 127.0.0.1:8765)")
	_ = fs.Parse(args)

	mgr, activeProj, err := initManager(*dataDir, *project)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer mgr.Close()

	broker, err := initBroker()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer broker.Close()

	modelRouter := initRouter()
	cognitiveWorker := worker.NewCognitiveWorker(broker, mgr, modelRouter)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := cognitiveWorker.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: worker start: %v\n", err)
	}

	sock := *socketPath
	if sock == "" {
		home, _ := os.UserHomeDir()
		sock = filepath.Join(home, ".coppermind", "coppermind.sock")
	}

	d := daemon.NewDaemon(daemon.Config{
		SocketPath: sock,
		TCPAddr:    *tcpAddr,
	}, mgr, broker, cognitiveWorker)

	if err := d.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Daemon failed to start: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("🤖 Coppermind daemon active (vault %q) and listening for MCP connections:\n", activeProj)
	if sock != "" {
		fmt.Printf("• Unix Domain Socket: %s\n", sock)
	}
	if *tcpAddr != "" {
		fmt.Printf("• TCP Address: %s\n", *tcpAddr)
	}
	fmt.Println("Press Ctrl+C to terminate.")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\nShutting down Coppermind daemon...")
	_ = d.Stop()
}

func runDoctor(args []string) {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "Data directory")
	_ = fs.Parse(args)

	dir := *dataDir
	if dir == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			dir = filepath.Join(home, ".coppermind")
		} else {
			dir = ".coppermind"
		}
	}

	fmt.Println("🏥 Running Coppermind 10-Pillar Diagnostic Inspection...")
	fmt.Printf("• Target Data Directory: %s\n\n", dir)

	results := doctor.RunDiagnostics(context.Background(), dir)
	allPassed := true
	hasWarnings := false
	for _, p := range results {
		icon := "✓"
		if p.Status == doctor.StatusWarn {
			icon = "⚠️"
			hasWarnings = true
		} else if p.Status == doctor.StatusFail {
			icon = "❌"
			allPassed = false
		}
		fmt.Printf("%s [%s] %-35s (%v)\n   %s\n", icon, p.Status, p.Name, p.Latency.Round(time.Microsecond), p.Message)
	}

	fmt.Println()
	if allPassed && !hasWarnings {
		fmt.Println("🎉 All Coppermind health pillars PASSED! Cognitive brain is healthy and operating within SLAs.")
	} else if allPassed && hasWarnings {
		fmt.Println("⚠️ Diagnostic warnings detected. Operational, but some cluster services are offline or unconfigured.")
	} else {
		fmt.Println("❌ Diagnostic failures detected. Please review the output above.")
	}
}

func runHook(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: coppermind hook <install|uninstall|status> [--repo <path>]")
		os.Exit(1)
	}

	action := args[0]
	fs := flag.NewFlagSet("hook "+action, flag.ExitOnError)
	repo := fs.String("repo", ".", "Repository root directory")
	_ = fs.Parse(args[1:])

	switch action {
	case "install":
		hookPath, err := hook.InstallGitHook(*repo)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to install git hook: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ Successfully installed automated episodic git commit hook!\n• Hook Path: %s\n", hookPath)
	case "uninstall", "remove":
		if err := hook.UninstallGitHook(*repo); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to uninstall git hook: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ Successfully uninstalled git commit hook from %s\n", *repo)
	case "status":
		installed, err := hook.StatusGitHook(*repo)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error inspecting git hook: %v\n", err)
			os.Exit(1)
		}
		if installed {
			fmt.Printf("✓ Coppermind episodic git hook is ACTIVE in %s\n", *repo)
		} else {
			fmt.Printf("• Coppermind episodic git hook is NOT installed in %s\n", *repo)
		}
	default:
		fmt.Fprintf(os.Stderr, "Unknown hook action: %q. Expected 'install', 'uninstall', or 'status'\n", action)
		os.Exit(1)
	}
}

func runProject(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: coppermind project <list|use|create|delete> [name]")
		os.Exit(1)
	}

	action := args[0]
	fs := flag.NewFlagSet("project "+action, flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "Data directory")
	_ = fs.Parse(args[1:])

	pm := project.NewManager(*dataDir)

	switch action {
	case "list", "ls":
		projects, err := pm.ListProjects()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error listing projects: %v\n", err)
			os.Exit(1)
		}
		cfg, _ := pm.LoadConfig()
		active := cfg.CurrentProject
		if active == "" {
			active = "github"
		}
		fmt.Println("Coppermind Project Vaults:")
		for _, p := range projects {
			mark := "  "
			if p.Name == active || p.IsActive {
				mark = "* "
			}
			fmt.Printf("%s%-16s (%s)\n", mark, p.Name, p.DBPath)
		}

	case "use", "switch":
		rest := fs.Args()
		if len(rest) == 0 {
			fmt.Fprintf(os.Stderr, "Error: project name required\nUsage: coppermind project use <name>\n")
			os.Exit(1)
		}
		name := rest[0]
		if err := pm.SetCurrentProject(name); err != nil {
			fmt.Fprintf(os.Stderr, "Error switching project: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ Switched active project vault to %q\n", name)

	case "create", "new":
		rest := fs.Args()
		if len(rest) == 0 {
			fmt.Fprintf(os.Stderr, "Error: project name required\nUsage: coppermind project create <name>\n")
			os.Exit(1)
		}
		name := rest[0]
		p, err := pm.CreateProject(name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating project: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ Created project vault %q at %s\n", name, p.DataDir)

	case "delete", "rm":
		rest := fs.Args()
		if len(rest) == 0 {
			fmt.Fprintf(os.Stderr, "Error: project name required\nUsage: coppermind project delete <name>\n")
			os.Exit(1)
		}
		name := rest[0]
		if err := pm.DeleteProject(name); err != nil {
			fmt.Fprintf(os.Stderr, "Error deleting project: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ Deleted project vault %q\n", name)

	default:
		fmt.Fprintf(os.Stderr, "Unknown project action: %q. Use list, use, create, delete\n", action)
		os.Exit(1)
	}
}

func runStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "Data directory")
	project := fs.String("project", "", "Target project vault")
	_ = fs.Parse(args)

	mgr, activeProj, err := initManager(*dataDir, *project)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer mgr.Close()

	total, err := mgr.Count(context.Background(), "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	profile := getProfile()
	fmt.Println("Coppermind Brain Status:")
	fmt.Printf("• Runtime Profile: Profile %s\n", strings.ToUpper(profile[:1])+profile[1:])
	fmt.Printf("• Active Project Vault: %s\n", activeProj)
	if profile == "cluster" {
		fmt.Println("• Storage Backend: PostgreSQL 17 + pgvector")
		fmt.Println("• Working Memory: Redis Cluster / Dragonfly RESP")
		fmt.Println("• Message Broker: RabbitMQ AMQP 0-9-1")
	} else {
		fmt.Printf("• Database Path: %s\n", getDBPath(*dataDir, *project))
		fmt.Println("• Storage Backend: Pure-Go SQLite WAL Mode")
		fmt.Println("• Working Memory: In-Memory RESP Scratchpad")
		fmt.Println("• Message Broker: In-Memory Topic Bus")
	}
	fmt.Printf("• Total Stored Memories: %s\n", strconv.Itoa(total))
	fmt.Println("• Embedding Engine: 128-dim FastText-style Subword/N-Gram Hashing")
	fmt.Println("• Interface: Model Context Protocol (MCP) over STDIO")
}
