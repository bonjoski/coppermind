package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/capsule"
	"github.com/bonjoski/coppermind/pkg/embedding"
	"github.com/bonjoski/coppermind/pkg/mcp"
	"github.com/bonjoski/coppermind/pkg/queue"
	"github.com/bonjoski/coppermind/pkg/router"
	"github.com/bonjoski/coppermind/pkg/scratchpad"
	"github.com/bonjoski/coppermind/pkg/seeder"
	"github.com/bonjoski/coppermind/pkg/storage/sqlite"
	"github.com/bonjoski/coppermind/pkg/worker"
)

var Version = "0.1.0-mvp"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	switch command {
	case "mcp", "daemon":
		runMCP(os.Args[2:])
	case "remember":
		runRemember(os.Args[2:])
	case "recall":
		runRecall(os.Args[2:])
	case "scratchpad":
		runScratchpad(os.Args[2:])
	case "dispatch":
		runDispatch(os.Args[2:])
	case "seed":
		runSeed(os.Args[2:])
	case "export":
		runExport(os.Args[2:])
	case "import":
		runImport(os.Args[2:])
	case "status":
		runStatus(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Printf("coppermind version %s\n", Version)
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
  remember     Store an architectural fact, decision, or runbook into memory
  recall       Perform semantic similarity search over stored memories
  scratchpad   Interact with fast in-memory working state (get, set, keys)
  dispatch     Enqueue an asynchronous cognitive task onto the message bus
  seed         Ingest markdown files or directories into memory
  export       Export the brain into a portable, verified capsule archive
  import       Restore a brain from a capsule archive with path traversal checks
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

func getDBPath(dataDir string) string {
	if dataDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			dataDir = ".coppermind"
		} else {
			dataDir = filepath.Join(home, ".coppermind")
		}
	}
	_ = os.MkdirAll(dataDir, 0700)
	return filepath.Join(dataDir, "coppermind.db")
}

func initManager(dataDir string) (*brain.Manager, error) {
	dbPath := getDBPath(dataDir)
	store, err := sqlite.NewSQLiteStore(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open storage at %s: %w", dbPath, err)
	}

	embedder := embedding.NewLocalHashEmbedder(128)
	sp := scratchpad.NewMemoryScratchpad()
	return brain.NewManager(store, embedder, sp), nil
}

func initBroker() (queue.Broker, error) {
	amqpURL := os.Getenv("COPPERMIND_RABBITMQ_URL")
	if amqpURL != "" {
		return queue.NewRabbitMQBroker(amqpURL, "coppermind.tasks")
	}
	return queue.NewEmbeddedBroker(256), nil
}

func initRouter() router.ModelRouter {
	endpoint := os.Getenv("COPPERMIND_LITELLM_URL")
	apiKey := os.Getenv("COPPERMIND_OPENAI_API_KEY")
	return router.NewLiteLLMRouter(endpoint, apiKey)
}

func runMCP(args []string) {
	fs := flag.NewFlagSet("mcp", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "Data directory for database files")
	_ = fs.Parse(args)

	mgr, err := initManager(*dataDir)
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

	if err := server.ServeSTDIO(ctx, os.Stdin); err != nil {
		fmt.Fprintf(os.Stderr, "MCP server stopped: %v\n", err)
		os.Exit(1)
	}
}

func runRemember(args []string) {
	fs := flag.NewFlagSet("remember", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "Data directory")
	category := fs.String("category", "general", "Category (architecture, convention, decision, runbook)")
	session := fs.String("session", "default", "Session or worktree identifier")
	_ = fs.Parse(args)

	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintf(os.Stderr, "Error: content is required\nUsage: coppermind remember [--category <cat>] <content>\n")
		os.Exit(1)
	}
	content := strings.Join(rest, " ")

	mgr, err := initManager(*dataDir)
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
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error storing memory: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Stored memory [%s] in category %q: %s\n", node.ID, node.Category, node.Content)
}

func runRecall(args []string) {
	fs := flag.NewFlagSet("recall", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "Data directory")
	category := fs.String("category", "", "Optional category filter")
	session := fs.String("session", "", "Optional session filter")
	limit := fs.Int("limit", 5, "Maximum results to retrieve")
	minScore := fs.Float64("min-score", 0.0, "Minimum cosine score threshold")
	_ = fs.Parse(args)

	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintf(os.Stderr, "Error: search query is required\nUsage: coppermind recall [--limit 5] <query>\n")
		os.Exit(1)
	}
	query := strings.Join(rest, " ")

	mgr, err := initManager(*dataDir)
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
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error recalling memory: %v\n", err)
		os.Exit(1)
	}

	if len(results) == 0 {
		fmt.Println("No matching memories found.")
		return
	}

	fmt.Printf("Found %d matching memories for %q:\n\n", len(results), query)
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
	sp := scratchpad.NewMemoryScratchpad()
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
	_ = fs.Parse(args)

	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintf(os.Stderr, "Error: task_type is required\nUsage: coppermind dispatch [--session <sess>] <summarize_session|deep_reflect|defrag_memory>\n")
		os.Exit(1)
	}
	taskType := queue.TaskType(rest[0])

	mgr, err := initManager(*dataDir)
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
	category := fs.String("category", "documentation", "Default category for ingested documents")
	_ = fs.Parse(args)

	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintf(os.Stderr, "Error: path to markdown file or directory is required\nUsage: coppermind seed [--category <cat>] <path>\n")
		os.Exit(1)
	}
	targetPath := rest[0]

	mgr, err := initManager(*dataDir)
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
		fmt.Printf("Seeding Coppermind from directory %s...\n", targetPath)
		count, err = seeder.IngestDirectory(ctx, mgr, targetPath, *category)
	} else {
		fmt.Printf("Seeding Coppermind from file %s...\n", targetPath)
		count, err = seeder.IngestFile(ctx, mgr, targetPath, *category)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Seeding failed: %v\n", err)
		os.Exit(1)
	}

	total, _ := mgr.Count(ctx, "")
	fmt.Printf("✓ Successfully ingested %d knowledge chunks into Coppermind! (Total memories in brain: %d)\n", count, total)
}

func runExport(args []string) {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "Data directory")
	outPath := fs.String("out", "coppermind.capsule", "Output capsule path")
	_ = fs.Parse(args)

	dbPath := getDBPath(*dataDir)
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
	_ = fs.Parse(args)

	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintf(os.Stderr, "Error: capsule path is required\nUsage: coppermind import <capsule.capsule>\n")
		os.Exit(1)
	}
	capsulePath := rest[0]
	targetDB := getDBPath(*dataDir)

	manifest, err := capsule.ImportCapsule(context.Background(), capsulePath, targetDB, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Import failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Successfully restored brain capsule from %s\n", capsulePath)
	fmt.Printf("• Restored Records: %d\n", manifest.TotalRecords)
	fmt.Printf("• Verified Checksum: %s\n", manifest.DBChecksum)
}

func runStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "Data directory")
	_ = fs.Parse(args)

	mgr, err := initManager(*dataDir)
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

	fmt.Println("Coppermind Brain Status:")
	fmt.Printf("• Database Path: %s\n", getDBPath(*dataDir))
	fmt.Printf("• Total Stored Memories: %s\n", strconv.Itoa(total))
	fmt.Println("• Storage Backend: Pure-Go SQLite WAL Mode")
	fmt.Println("• Embedding Engine: 128-dim FastText-style Subword/N-Gram Hashing")
	fmt.Println("• Interface: Model Context Protocol (MCP) over STDIO")
}
