package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/bonjoski/coppermind/pkg/authz"
	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/capsule"
	"github.com/bonjoski/coppermind/pkg/daemon"
	"github.com/bonjoski/coppermind/pkg/doctor"
	"github.com/bonjoski/coppermind/pkg/embedding"
	"github.com/bonjoski/coppermind/pkg/hook"
	"github.com/bonjoski/coppermind/pkg/indexer"
	"github.com/bonjoski/coppermind/pkg/keystore"
	"github.com/bonjoski/coppermind/pkg/lenses"
	"github.com/bonjoski/coppermind/pkg/mcp"
	"github.com/bonjoski/coppermind/pkg/project"
	"github.com/bonjoski/coppermind/pkg/queue"
	"github.com/bonjoski/coppermind/pkg/radar"
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
	case "capsule":
		runCapsule(cmdArgs)
	case "requirements":
		runRequirements(cmdArgs)
	case "distill":
		runDistill(cmdArgs)
	case "verify":
		runVerify(cmdArgs)
	case "vacuum", "gc":
		runVacuum(cmdArgs)
	case "project", "projects":
		runProject(cmdArgs)
	case "config":
		runConfig(cmdArgs)
	case "doctor":
		runDoctor(cmdArgs)
	case "hook":
		runHook(cmdArgs)
	case "observations", "obs":
		runObservations(cmdArgs)
	case "proposals", "proposal":
		runProposals(cmdArgs)
	case "radar":
		runRadar(cmdArgs)
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
  capsule      Manage Security Mentor & Requirements Capsules (keygen, sign, pack, import, list, verify, export)
  requirements Generate <=3 sprint-ready Given/When/Then abuse-case acceptance criteria (ephemeral)
  distill      Distill a sanitized post-mortem lesson into MentorCard, AbuseCaseCriterion, and Aegisbox probe JSON
  verify       Audit cryptographic Merkle chain integrity for a session
  vacuum       Purge expired TTL memories and compact SQLite storage
  project      Manage isolated vaults (list, use, create, delete)
  config       Display or update persistent configuration (provider, model, endpoint)
  doctor       Execute the 11-pillar diagnostic inspection suite
  hook         Manage Git episodic capture and Stormcage diff integrity hooks (install, uninstall, status, check, verify-diff)
  observations List, filter, and resolve cognitive lens observations (alias: obs)
  proposals    Review, approve, or reject quarantined memory proposals
  radar        Synchronize or inspect industry standards and threat intelligence feeds
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
	dataDir := os.Getenv("COPPERMIND_DATA_DIR")
	pm := project.NewManager(dataDir)
	cfg, _ := pm.LoadConfig()

	provider := strings.ToLower(strings.TrimSpace(os.Getenv("COPPERMIND_PROVIDER")))
	if provider == "" && cfg.Provider != "" {
		provider = strings.ToLower(strings.TrimSpace(cfg.Provider))
	}

	endpoint := os.Getenv("COPPERMIND_LITELLM_URL")
	if endpoint == "" && cfg.Endpoint != "" {
		endpoint = cfg.Endpoint
	}

	model := os.Getenv("COPPERMIND_MODEL")
	if model == "" && cfg.Model != "" {
		model = cfg.Model
	}

	apiKey := os.Getenv("COPPERMIND_API_KEY")
	if apiKey == "" && cfg.APIKey != "" {
		apiKey = cfg.APIKey
	}

	ks := keystore.NewLocksmithKeystore()

	// If Gemini is explicitly configured or selected
	if provider == "gemini" {
		if apiKey == "" {
			apiKey = os.Getenv("GEMINI_API_KEY")
			if apiKey == "" {
				apiKey = os.Getenv("GEMINI-API-KEY")
			}
		}
		if apiKey == "" {
			apiKey, _ = ks.GetSecret(context.Background(), "GEMINI-API-KEY")
			if apiKey == "" {
				apiKey, _ = ks.GetSecret(context.Background(), "GEMINI_API_KEY")
			}
		}
		if endpoint == "" {
			endpoint = "https://generativelanguage.googleapis.com/v1beta/openai"
		}
		if model == "" {
			model = "gemini-3.5-flash-lite"
		}
		if apiKey == "" && endpoint == "" {
			return router.NewLiteLLMRouter("", "")
		}
		return router.NewLiteLLMRouterWithModel(endpoint, apiKey, model)
	}

	// Multi-provider ambient / fallback:
	if apiKey == "" {
		apiKey = os.Getenv("OPENAI_API_KEY")
	}
	if apiKey == "" {
		apiKey = os.Getenv("GEMINI_API_KEY")
		if apiKey == "" {
			apiKey = os.Getenv("GEMINI-API-KEY")
		}
		if apiKey != "" && endpoint == "" {
			endpoint = "https://generativelanguage.googleapis.com/v1beta/openai"
			if model == "" {
				model = "gemini-3.5-flash-lite"
			}
		}
	}

	if endpoint == "" {
		endpoint = os.Getenv("OPENAI_BASE_URL")
	}

	if apiKey == "" {
		// Prioritize Gemini in Locksmith to leverage active biometric lease and avoid prompt stalls
		apiKey, _ = ks.GetSecret(context.Background(), "GEMINI-API-KEY")
		if apiKey == "" {
			apiKey, _ = ks.GetSecret(context.Background(), "GEMINI_API_KEY")
		}
		if apiKey != "" && endpoint == "" {
			endpoint = "https://generativelanguage.googleapis.com/v1beta/openai"
			if model == "" {
				model = "gemini-3.5-flash-lite"
			}
		} else if apiKey == "" {
			apiKey, _ = ks.GetSecret(context.Background(), "OPENAI_API_KEY")
		}
	}

	if endpoint == "" && apiKey == "" {
		// Offline fallback reflection mode; does not query keystore or prompt Touch ID
		return router.NewLiteLLMRouter("", "")
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

	// Initialize and start Cognitive Lenses engine
	lensCfg, _ := lenses.LoadConfig("")
	if lensCfg == nil {
		lensCfg = lenses.DefaultConfig()
	}
	lensEngine := lenses.NewEngine(lensCfg, broker, mgr, rtr, activeProj, nil)
	_ = lensEngine.Start(ctx)
	defer lensEngine.Stop()
	cw.SetLensEngine(lensEngine)

	if err := cw.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to start cognitive worker: %v\n", err)
	}
	defer cw.Stop()

	// Seed Working Memory scratchpad with top 3 unresolved high/critical observations for active project vault
	if mgr != nil {
		topObs, err := mgr.ListObservations(ctx, "", "", "open", "high", 3)
		if err == nil && len(topObs) > 0 {
			var sb strings.Builder
			sb.WriteString(fmt.Sprintf("Active High-Priority Observations for %q (%d):\n", activeProj, len(topObs)))
			for i, obs := range topObs {
				sb.WriteString(fmt.Sprintf("%d. [%s] (%s): %s\n", i+1, strings.ToUpper(obs.Severity), obs.SourceLens, obs.Content))
			}
			_ = mgr.Scratchpad().Set(ctx, "active_observations", sb.String(), 24*time.Hour)
		}
	}

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
	supersedes := fs.String("supersedes", "", "UUID of previous memory node to supersede and tombstone")
	rationale := fs.String("rationale", "", "Mandatory rationale when superseding an existing memory")
	advisory := fs.String("advisory", "", "Advisory reference (e.g. ADR-042)")
	role := fs.String("role", "", "Author role for epistemic validation (e.g. architect, product_owner, developer)")
	author := fs.String("author", "", "Author identity (email, handle, or key thumbprint)")
	provenanceStr := fs.String("provenance", string(brain.ProvenanceLocalWorkspace), "Provenance taint tier (TRUST_LOCAL_WORKSPACE, TAINT_SHARED_DOC, TAINT_EXTERNAL_USER, TAINT_UNTRUSTED_WEB)")
	_ = fs.Parse(args)

	provenance, provErr := brain.ParseProvenanceTier(*provenanceStr)
	if provErr != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", provErr)
		os.Exit(1)
	}

	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintf(os.Stderr, "Error: content is required\nUsage: coppermind remember [--category <cat>] [--supersedes <id>] <content>\n")
		os.Exit(1)
	}
	content := strings.Join(rest, " ")

	mgr, activeProj, err := initManager(*dataDir, *project)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer mgr.Close()

	authorRole := strings.TrimSpace(*role)
	if authorRole == "" {
		if *category == "architecture" || *category == "convention" {
			authorRole = "developer"
		} else {
			authorRole = "contributor"
		}
	}
	authorID := strings.TrimSpace(*author)
	if authorID == "" {
		authorID = os.Getenv("USER")
		if authorID == "" {
			authorID = "local-operator"
		}
	}

	enforcer := authz.NewDefaultPolicyEnforcer()
	claims := authz.SubjectClaims{
		Subject: authorID,
		Role:    authorRole,
	}

	writeReq := authz.MemoryWriteRequest{
		Category:     *category,
		Content:      content,
		SupersedesID: supersedes,
		Rationale:    *rationale,
		AdvisoryRef:  *advisory,
	}

	tier, status, authErr := enforcer.AuthorizeWrite(context.Background(), claims, writeReq)
	if authErr != nil && status == authz.StatusRejected {
		fmt.Fprintf(os.Stderr, "Error: %v (role %q cannot write category %q)\n", authErr, authorRole, *category)
		os.Exit(43)
	}

	if *supersedes != "" && *rationale == "" {
		fmt.Fprintf(os.Stderr, "Error: --rationale is required when superseding an existing memory node\n")
		os.Exit(1)
	}

	node, err := mgr.Remember(context.Background(), brain.RememberRequest{
		SessionID:       *session,
		Category:        *category,
		Content:         content,
		Provenance:      provenance,
		TTL:             *ttl,
		AuthorityTier:   authz.TierToString(tier),
		LifecycleStatus: string(status),
		AuthorIdentity:  authorID,
		AuthorRole:      authorRole,
		SupersedesID:    *supersedes,
		Rationale:       *rationale,
		AdvisoryRef:     *advisory,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error storing memory: %v\n", err)
		os.Exit(1)
	}

	expMsg := ""
	if node.ExpiresAt != nil {
		expMsg = fmt.Sprintf(" (expires %s)", node.ExpiresAt.Format("2006-01-02 15:04"))
	}

	if status == authz.StatusProposed {
		fmt.Printf("⚠ Write intercepted: role %q lacks authority for %s. Quarantined as PROPOSED observation [%s] in vault %q: %s\n",
			authorRole, node.AuthorityTier, node.ID, activeProj, node.Content)
	} else if *supersedes != "" {
		fmt.Printf("✓ Stored memory [%s] in vault %q (superseded [%s], %s)%s: %s\n",
			node.ID, activeProj, *supersedes, node.AuthorityTier, expMsg, node.Content)
	} else {
		fmt.Printf("✓ Stored memory [%s] in vault %q [%s | %s]%s: %s\n",
			node.ID, activeProj, node.AuthorityTier, node.Category, expMsg, node.Content)
	}
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
	lensName := fs.String("lens", "", "Filter recall to observations from a specific lens (e.g. mentor, security-architect, systems-architect)")
	sdkHints := fs.String("sdk", "", "Optional comma-separated SDK hints for --lens mentor (e.g. openai,mcp,pgvector)")
	includeObs := fs.Bool("include-observations", true, "Auto-attach linked cognitive lens observations to primary recalled memories")
	includeSuperseded := fs.Bool("include-superseded", false, "Include superseded historical memories in query results")
	tier := fs.String("tier", "", "Filter by specific authority tier (e.g. TIER_1_ARCHITECTURE)")
	asJSON := fs.Bool("json", false, "Emit machine-readable JSON output")
	showWhy := fs.Bool("why", false, "Include detailed explanations where supported")
	_ = fs.Parse(args)

	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintf(os.Stderr, "Error: search query is required\nUsage: coppermind recall [--limit 5] [--lens <name>] [--json] [--include-observations] <query>\n")
		os.Exit(1)
	}
	query := strings.Join(rest, " ")

	mgr, activeProj, err := initManager(*dataDir, *project)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer mgr.Close()

	// Fast-path: Mentor Cognitive Lens (sub-5ms lock-free WAL read, max 2 cards, <=120 tokens/nudge)
	if strings.EqualFold(strings.TrimSpace(*lensName), "mentor") {
		var sdks []string
		if strings.TrimSpace(*sdkHints) != "" {
			for _, part := range strings.Split(*sdkHints, ",") {
				if trimmed := strings.TrimSpace(part); trimmed != "" {
					sdks = append(sdks, trimmed)
				}
			}
		}
		mentorLens := lenses.NewSQLiteMentorLens(mgr.Store(), embedding.NewLocalHashEmbedder(128))
		nudges, err := mentorLens.MatchContext(context.Background(), query, sdks, *limit)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error recalling mentor nudges: %v\n", err)
			os.Exit(1)
		}
		if *asJSON {
			if nudges == nil {
				nudges = []lenses.MentorNudge{}
			}
			enc := json.NewEncoder(os.Stdout)
			_ = enc.Encode(map[string]any{"lens": "mentor", "query": query, "nudges": nudges})
			return
		}
		if len(nudges) == 0 {
			fmt.Println("No matching security mentor nudges found. Import capsules with `coppermind capsule import <file>`.")
			return
		}
		fmt.Println(lenses.FormatMentorNudges(nudges))
		return
	}

	// Fast-path: PO & Requirements Cognitive Lens (sub-5ms ephemeral read-only, max 3 criteria, <=180 tokens)
	if strings.EqualFold(strings.TrimSpace(*lensName), "requirements") || strings.EqualFold(strings.TrimSpace(*lensName), "po-mentor") {
		reqLens := lenses.NewSQLiteRequirementsLens(mgr.Store(), embedding.NewLocalHashEmbedder(128))
		criteria, err := reqLens.SuggestCriteriaContext(context.Background(), query, nil, *limit)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error suggesting requirements criteria: %v\n", err)
			os.Exit(1)
		}
		if *asJSON {
			out, err := lenses.FormatRequirementsJSON(criteria, *showWhy)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error formatting requirements JSON: %v\n", err)
				os.Exit(1)
			}
			fmt.Println(out)
			return
		}
		fmt.Println(lenses.FormatRequirementsMarkdown(criteria, *showWhy))
		return
	}

	results, err := mgr.Recall(context.Background(), brain.RecallRequest{
		SessionID:           *session,
		Category:            *category,
		Query:               query,
		Limit:               *limit,
		MinScore:            float32(*minScore),
		Hybrid:              *hybrid,
		GitRepo:             *repo,
		GitBranch:           *branch,
		SourceLens:          *lensName,
		IncludeObservations: *includeObs,
		IncludeSuperseded:   *includeSuperseded,
		AuthorityTier:       *tier,
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
		isLearning := r.Node.Category == "learning" ||
			r.Node.Category == "architectural-learning" ||
			r.Node.Category == "lesson" ||
			r.Node.Category == "learnings" ||
			strings.Contains(r.Node.Content, "[ARCHITECTURAL LEARNING") ||
			strings.Contains(r.Node.Content, "**Remediation:**") ||
			strings.Contains(r.Node.Content, "**remediation:**")

		tierBadge := r.Node.AuthorityTier
		catBadge := r.Node.Category
		if isLearning && !strings.Contains(catBadge, "learning") {
			catBadge = catBadge + " (learning)"
		}

		fmt.Printf("%d. [Score: %.3f] [%s | %s | %s]\n",
			i+1, r.Score, tierBadge, catBadge, r.Node.SessionID)

		if isLearning {
			fmt.Println("   💡 ARCHITECTURAL LEARNING / INVARIANT:")
		}
		fmt.Printf("   %s\n", r.Node.Content)

		if len(r.Observations) > 0 {
			synthesizerObs := 0
			for _, obs := range r.Observations {
				if obs.SourceLens == "synthesizer" {
					synthesizerObs++
				}
			}
			if synthesizerObs > 0 {
				fmt.Printf("   ↳ Synthesized Architectural Learnings (%d):\n", len(r.Observations))
			} else {
				fmt.Printf("   ↳ Linked Observations (%d):\n", len(r.Observations))
			}
			for _, obs := range r.Observations {
				fmt.Printf("     • [%s] (%s): %s\n",
					strings.ToUpper(obs.Severity), obs.SourceLens, obs.Content)
			}
		}
		fmt.Println()
	}
}

func runScratchpad(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: coppermind scratchpad <get|set|delete|keys> [key] [value]")
		os.Exit(1)
	}
	action := args[0]
	var rawSP brain.Scratchpad
	if getProfile() == "cluster" {
		redisAddr := os.Getenv("COPPERMIND_REDIS_ADDR")
		if redisAddr == "" {
			redisAddr = "127.0.0.1:6379"
		}
		rawSP = scratchpad.NewRedisScratchpad(redisAddr)
	} else {
		rawSP = scratchpad.NewMemoryScratchpad()
	}
	sp := brain.NewValidatedScratchpad(rawSP, brain.NewMemoryValidator(), "cli-scratchpad", brain.ProvenanceSharedDoc)
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
		if err := sp.Set(ctx, args[1], args[2], 0); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Set %q\n", args[1])
	default:
		fmt.Fprintf(os.Stderr, "Unknown scratchpad action: %q\n", action)
		os.Exit(1)
	}
}

func runDispatch(args []string) {
	fs := flag.NewFlagSet("dispatch", flag.ExitOnError)
	session := fs.String("session", "", "Target session or worktree (default all)")
	dataDir := fs.String("data-dir", "", "Data directory")
	project := fs.String("project", "", "Target project vault")
	_ = fs.Parse(args)

	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintf(os.Stderr, "Error: task_type is required\nUsage: coppermind dispatch [--session <sess>] <reflect|summarize_session|deep_reflect|extract_decisions|defrag_memory|index_git_tree>\n")
		os.Exit(1)
	}
	taskType := queue.TaskType(rest[0])

	mgr, activeProj, err := initManager(*dataDir, *project)
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

	// Special handling for dispatch reflect
	if taskType == "reflect" {
		rfs := flag.NewFlagSet("reflect", flag.ExitOnError)
		lensName := rfs.String("lens", "all", "Target lens to execute (e.g. red-team, security-architect, systems-architect, drift-auditor, synthesizer, devils-advocate, or all)")
		sinceStr := rfs.String("since", "0", "Time window for candidate memories (e.g. 1h, 24h, 7d, or 0 for all)")
		limit := rfs.Int("limit", 100, "Maximum candidate memories to evaluate")
		crossVault := rfs.Bool("cross-vault", false, "Execute across project vaults")
		_ = rfs.Parse(rest[1:])

		var sinceDur time.Duration
		if *sinceStr != "" && *sinceStr != "0" && *sinceStr != "all" {
			sinceDur, _ = time.ParseDuration(*sinceStr)
			if sinceDur == 0 && strings.HasSuffix(*sinceStr, "d") {
				days, _ := strconv.Atoi(strings.TrimSuffix(*sinceStr, "d"))
				sinceDur = time.Duration(days) * 24 * time.Hour
			}
		}

		lensCfg, err := lenses.LoadConfig("")
		if err != nil {
			lensCfg = lenses.DefaultConfig()
		}
		engine := lenses.NewEngine(lensCfg, broker, mgr, rtr, activeProj, nil)
		cw.SetLensEngine(engine)

		if err := cw.Start(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "Error starting worker: %v\n", err)
			os.Exit(1)
		}
		defer cw.Stop()

		fmt.Printf("Executing Cognitive Lens reflection (--lens %s, --since %s, limit=%d) in vault %q...\n", *lensName, *sinceStr, *limit, activeProj)
		res, err := engine.Reflect(ctx, lenses.ReflectRequest{
			Lens:       *lensName,
			Since:      sinceDur,
			CrossVault: *crossVault,
			Project:    activeProj,
			SessionID:  *session,
			Limit:      *limit,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Reflection failed: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("✓ Reflection completed: %d candidates evaluated, %d skipped by pre-filter, %d observations generated\n\n",
			res.EvaluatedCount, res.SkippedCount, len(res.Observations))
		for i, obs := range res.Observations {
			fmt.Printf("%d. [%s] (%s): %s\n", i+1, strings.ToUpper(obs.Severity), obs.SourceLens, obs.Content)
		}
		return
	}

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

	fmt.Println("🏥 Running Coppermind 11-Pillar Diagnostic Inspection...")
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
		fmt.Println("Usage: coppermind hook <install|uninstall|status|check|verify-diff> [--repo <path>]")
		os.Exit(1)
	}

	action := args[0]
	fs := flag.NewFlagSet("hook "+action, flag.ExitOnError)
	repo := fs.String("repo", ".", "Repository root directory")
	ref := fs.String("ref", "HEAD", "Git revision or range to inspect (e.g. HEAD or ORIG_HEAD..HEAD)")
	session := fs.String("session", "default", "Session or repository name for taint tracking")
	provenanceStr := fs.String("provenance", string(brain.ProvenanceSharedDoc), "Provenance taint tier for diff verification")
	fromStdin := fs.Bool("stdin", false, "Read unified git diff content from standard input")
	jsonOut := fs.Bool("json", false, "Emit structured JSON verdict")
	_ = fs.Parse(args[1:])

	switch action {
	case "install":
		hookPath, err := hook.InstallGitHook(*repo)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to install git hook: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ Successfully installed automated episodic git capture & diff integrity hooks!\n• Hook Path: %s\n", hookPath)
	case "uninstall", "remove":
		if err := hook.UninstallGitHook(*repo); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to uninstall git hook: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ Successfully uninstalled git commit & merge integrity hooks from %s\n", *repo)
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
	case "verify-diff":
		prov, provErr := brain.ParseProvenanceTier(*provenanceStr)
		if provErr != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", provErr)
			os.Exit(1)
		}

		var diffText string
		signed := prov == brain.ProvenanceLocalWorkspace
		if *fromStdin {
			data, err := io.ReadAll(io.LimitReader(os.Stdin, 2*1024*1024))
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to read diff from stdin: %v\n", err)
				os.Exit(1)
			}
			diffText = string(data)
		} else {
			var gitArgs []string
			if strings.Contains(*ref, "..") {
				gitArgs = []string{"-C", *repo, "diff", "--no-color", *ref}
			} else {
				gitArgs = []string{"-C", *repo, "show", "--no-color", "--format=", *ref}
			}
			out, err := exec.Command("git", gitArgs...).Output()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to read git diff for %q in %s: %v\n", *ref, *repo, err)
				os.Exit(1)
			}
			diffText = string(out)
		}

		repoName := filepath.Base(*repo)
		validator := brain.NewMemoryValidator()
		verdict, err := validator.VerifyGitDiff(context.Background(), *session, diffText, "", signed, repoName, *ref)
		if err != nil {
			if *jsonOut {
				enc, _ := json.MarshalIndent(map[string]any{
					"status":     "rejected",
					"error":      err.Error(),
					"provenance": prov,
					"ref":        *ref,
				}, "", "  ")
				fmt.Println(string(enc))
			} else {
				fmt.Fprintf(os.Stderr, "🚨 Episodic Memory Integrity Hook REJECTED diff (%s): %v\n", *ref, err)
			}
			os.Exit(1)
		}

		if *jsonOut {
			enc, _ := json.MarshalIndent(verdict, "", "  ")
			fmt.Println(string(enc))
		} else {
			fmt.Printf("✓ Diff verified by embedded Stormcage engine (decision=%s taint=%s score=%.2f quarantined=%t digest=%s)\n",
				verdict.StormcageDecision, verdict.EffectiveTaint, verdict.TaintScore, verdict.Quarantined, verdict.IntegrityDigest[:12])
		}
	case "check":
		repoRoot := *repo
		mgr, activeProj, err := initManager("", "")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening vault: %v\n", err)
			os.Exit(1)
		}
		defer mgr.Close()

		repoName := filepath.Base(repoRoot)
		obs, err := mgr.ListObservations(context.Background(), repoName, "", "open", "high", 10)
		if err != nil || len(obs) == 0 {
			obs, _ = mgr.ListObservations(context.Background(), "", "", "open", "high", 10)
		}

		if len(obs) == 0 {
			fmt.Printf("✓ No unresolved high or critical observations in vault %q.\n", activeProj)
		} else {
			fmt.Printf("⚠️  Found %d unresolved high/critical observations in vault %q:\n", len(obs), activeProj)
			for _, o := range obs {
				firstLine := strings.Split(o.Content, "\n")[0]
				fmt.Printf("  • [%s] %s: %s (ID: %s)\n", strings.ToUpper(o.Severity), o.SourceLens, firstLine, o.ID)
			}
		}
	default:
		fmt.Fprintf(os.Stderr, "Unknown hook action: %q. Expected 'install', 'uninstall', 'status', 'check', or 'verify-diff'\n", action)
		os.Exit(1)
	}
}

func runObservations(args []string) {
	fs := flag.NewFlagSet("observations", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "Data directory for database files")
	project := fs.String("project", "", "Target project vault (e.g. github, personal, work)")
	session := fs.String("session", "", "Filter by session or worktree")
	lens := fs.String("lens", "", "Filter by source lens (e.g. red-team, security-architect, devils-advocate)")
	status := fs.String("status", "open", "Filter by status: open, resolved, or all")
	minSev := fs.String("min-severity", "", "Minimum severity filter: info, low, medium, high, critical")
	resolveID := fs.String("resolve", "", "Mark an observation ID as resolved")
	limit := fs.Int("limit", 50, "Maximum observations to display")
	_ = fs.Parse(args)

	mgr, activeProj, err := initManager(*dataDir, *project)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer mgr.Close()

	ctx := context.Background()

	if *resolveID != "" {
		if err := mgr.ResolveObservation(ctx, *resolveID); err != nil {
			fmt.Fprintf(os.Stderr, "Error resolving observation %s: %v\n", *resolveID, err)
			os.Exit(1)
		}
		fmt.Printf("✓ Successfully resolved observation %s in vault %s\n", *resolveID, activeProj)
		return
	}

	filterStatus := *status
	if filterStatus == "all" {
		filterStatus = ""
	}

	obs, err := mgr.ListObservations(ctx, *session, *lens, filterStatus, *minSev, *limit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing observations: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Coppermind Cognitive Observations (Vault: %s, Status: %s, Lens: %s)\n", activeProj, *status, *lens)
	fmt.Println(strings.Repeat("=", 80))

	if len(obs) == 0 {
		fmt.Println("No matching observations found.")
		return
	}

	for i, node := range obs {
		fmt.Printf("\n%s", FormatObservation(node, i+1))
	}
	fmt.Println()
}

// FormatObservation formats an observation node for display in the observations CLI.
func FormatObservation(node *brain.MemoryNode, index int) string {
	var sb strings.Builder
	sevBadge := strings.ToUpper(node.Severity)
	statusBadge := strings.ToUpper(node.Status)
	if statusBadge == "" {
		statusBadge = "OPEN"
	}
	sb.WriteString(fmt.Sprintf("[%d] %s (%s) — %s [ID: %s]\n", index, sevBadge, node.SourceLens, statusBadge, node.ID))
	sb.WriteString(fmt.Sprintf("    Created: %s\n", node.CreatedAt.Format(time.RFC3339)))
	if len(node.ParentIDs) > 0 {
		sb.WriteString(fmt.Sprintf("    Parent Memories: %s\n", strings.Join(node.ParentIDs, ", ")))
	}
	if node.Metadata != nil {
		if node.Metadata["unverified_poc"] == "true" {
			sb.WriteString("  ⚠️  [UNVERIFIED POC: Demoted to Info]\n")
		}
		if ep, ok := node.Metadata["entry_point"]; ok && ep != "" {
			sb.WriteString(fmt.Sprintf("  Entry Point: %s\n", ep))
		}
		if si, ok := node.Metadata["sibling_inconsistency"]; ok && si != "" {
			sb.WriteString(fmt.Sprintf("  Sibling Inconsistency: %s\n", si))
		}
		if poc, ok := node.Metadata["poc"]; ok && poc != "" {
			sb.WriteString(fmt.Sprintf("  PoC: %s\n", poc))
		}
	}
	lines := strings.Split(node.Content, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if node.Metadata != nil {
			if node.Metadata["entry_point"] != "" && strings.HasPrefix(trimmed, "Entry Point: ") {
				continue
			}
			if node.Metadata["sibling_inconsistency"] != "" && strings.HasPrefix(trimmed, "Sibling Inconsistency: ") {
				continue
			}
			if node.Metadata["poc"] != "" && strings.HasPrefix(trimmed, "PoC: ") {
				continue
			}
		}
		sb.WriteString(fmt.Sprintf("    %s\n", line))
	}
	return sb.String()
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

func runConfig(args []string) {
	fs := flag.NewFlagSet("config", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "Data directory")
	_ = fs.Parse(args)

	rest := fs.Args()
	pm := project.NewManager(*dataDir)

	if len(rest) == 0 || rest[0] == "list" || (rest[0] == "get" && len(rest) == 1) {
		cfg, err := pm.LoadConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Coppermind Configuration:")
		proj := cfg.CurrentProject
		if proj == "" {
			proj = "github (default)"
		}
		fmt.Printf("  Active Project : %s\n", proj)
		provider := cfg.Provider
		if provider == "" {
			provider = "gemini (default)"
		}
		fmt.Printf("  Model Provider : %s\n", provider)
		model := cfg.Model
		if model == "" {
			model = "gemini-3.5-flash-lite (default)"
		}
		fmt.Printf("  Model Name     : %s\n", model)
		endpoint := cfg.Endpoint
		if endpoint == "" {
			endpoint = "https://generativelanguage.googleapis.com/v1beta/openai (default)"
		}
		fmt.Printf("  Endpoint       : %s\n", endpoint)
		return
	}

	switch rest[0] {
	case "get":
		if len(rest) < 2 {
			fmt.Println("Usage: coppermind config get <key>")
			os.Exit(1)
		}
		cfg, _ := pm.LoadConfig()
		key := strings.ToLower(strings.TrimSpace(rest[1]))
		switch key {
		case "provider":
			fmt.Println(cfg.Provider)
		case "model":
			fmt.Println(cfg.Model)
		case "endpoint":
			fmt.Println(cfg.Endpoint)
		case "project", "current_project":
			fmt.Println(cfg.CurrentProject)
		default:
			fmt.Fprintf(os.Stderr, "Unknown configuration key: %s\n", key)
			os.Exit(1)
		}

	case "set":
		if len(rest) < 3 {
			fmt.Println("Usage: coppermind config set <key> <value>")
			os.Exit(1)
		}
		cfg, _ := pm.LoadConfig()
		key := strings.ToLower(strings.TrimSpace(rest[1]))
		val := strings.TrimSpace(rest[2])
		switch key {
		case "provider":
			cfg.Provider = val
		case "model":
			cfg.Model = val
		case "endpoint":
			cfg.Endpoint = val
		case "project", "current_project":
			cfg.CurrentProject = val
		default:
			fmt.Fprintf(os.Stderr, "Unknown configuration key: %s\n", key)
			os.Exit(1)
		}
		if err := pm.SaveConfig(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to save configuration: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ Set %s = %s in config.json\n", key, val)

	default:
		fmt.Fprintf(os.Stderr, "Unknown config subcommand: %s. Use 'get', 'set', or no arguments to list.\n", rest[0])
		os.Exit(1)
	}
}

func runProposals(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: coppermind proposals <list|approve|reject> [id]")
		os.Exit(1)
	}

	action := args[0]
	fs := flag.NewFlagSet("proposals "+action, flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "Data directory")
	project := fs.String("project", "", "Target project vault")
	category := fs.String("category", "", "Optional category filter")
	_ = fs.Parse(args[1:])

	mgr, activeProj, err := initManager(*dataDir, *project)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer mgr.Close()

	ctx := context.Background()

	switch action {
	case "list", "ls":
		results, err := mgr.Recall(ctx, brain.RecallRequest{
			Query:             "*",
			Category:          *category,
			IncludeSuperseded: true,
			LifecycleStatus:   string(authz.StatusProposed),
			Limit:             50,
			MinScore:          0.0,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error listing proposals: %v\n", err)
			os.Exit(1)
		}
		if len(results) == 0 {
			fmt.Printf("No pending memory proposals found in vault %q.\n", activeProj)
			return
		}
		fmt.Printf("Pending Memory Proposals in vault %q (%d):\n\n", activeProj, len(results))
		for i, r := range results {
			author := r.Node.AuthorIdentity
			if author == "" {
				author = "anonymous"
			}
			role := r.Node.AuthorRole
			if role == "" {
				role = "unknown"
			}
			supMsg := ""
			if r.Node.SupersedesID != "" {
				supMsg = fmt.Sprintf(" [Supersedes: %s]", r.Node.SupersedesID)
			}
			fmt.Printf("%d. [%s] [%s | %s]%s\n   Author: %s (%s)\n   Content: %s\n",
				i+1, r.Node.ID, r.Node.AuthorityTier, r.Node.Category, supMsg, author, role, r.Node.Content)
			if r.Node.Rationale != "" {
				fmt.Printf("   Rationale: %s\n", r.Node.Rationale)
			}
			fmt.Println()
		}

	case "approve":
		rest := fs.Args()
		if len(rest) == 0 {
			fmt.Fprintf(os.Stderr, "Error: proposal ID required\nUsage: coppermind proposals approve <id>\n")
			os.Exit(1)
		}
		id := rest[0]
		node, err := mgr.Store().GetByID(ctx, id)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error fetching proposal %q: %v\n", id, err)
			os.Exit(1)
		}
		if node.LifecycleStatus != string(authz.StatusProposed) && node.LifecycleStatus != "PROPOSED" {
			fmt.Fprintf(os.Stderr, "Warning: node %s has status %q (not PROPOSED)\n", id, node.LifecycleStatus)
		}
		node.LifecycleStatus = string(authz.StatusActive)
		node.UpdatedAt = time.Now()
		if err := mgr.Store().Store(ctx, node); err != nil {
			fmt.Fprintf(os.Stderr, "Error approving proposal: %v\n", err)
			os.Exit(1)
		}
		if node.SupersedesID != "" {
			target, err := mgr.Store().GetByID(ctx, node.SupersedesID)
			if err == nil && target != nil {
				target.LifecycleStatus = string(authz.StatusSuperseded)
				target.SupersededByID = node.ID
				target.UpdatedAt = time.Now()
				_ = mgr.Store().Store(ctx, target)
			}
		}
		fmt.Printf("✓ Approved proposal [%s] in vault %q (promoted to ACTIVE %s)\n", node.ID, activeProj, node.AuthorityTier)

	case "reject":
		rest := fs.Args()
		if len(rest) == 0 {
			fmt.Fprintf(os.Stderr, "Error: proposal ID required\nUsage: coppermind proposals reject <id>\n")
			os.Exit(1)
		}
		id := rest[0]
		node, err := mgr.Store().GetByID(ctx, id)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error fetching proposal %q: %v\n", id, err)
			os.Exit(1)
		}
		node.LifecycleStatus = string(authz.StatusRejected)
		node.UpdatedAt = time.Now()
		if err := mgr.Store().Store(ctx, node); err != nil {
			fmt.Fprintf(os.Stderr, "Error rejecting proposal: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ Rejected proposal [%s] in vault %q (status: REJECTED)\n", node.ID, activeProj)

	default:
		fmt.Fprintf(os.Stderr, "Unknown proposals subcommand %q. Usage: coppermind proposals <list|approve|reject> [id]\n", action)
		os.Exit(1)
	}
}

func runRadar(args []string) {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: coppermind radar <sync|detect|list> [options]\n")
		os.Exit(1)
	}

	action := args[0]
	cmdArgs := args[1:]

	switch action {
	case "detect":
		fs := flag.NewFlagSet("radar detect", flag.ExitOnError)
		dirFlag := fs.String("dir", ".", "Directory to inspect for ecosystem manifests")
		_ = fs.Parse(cmdArgs)

		ecos := radar.DetectWorkspaceEcosystems(*dirFlag)
		fmt.Printf("Detected active ecosystems in %q:\n", *dirFlag)
		for _, e := range ecos {
			fmt.Printf("  • %s\n", e)
		}

	case "list", "ls":
		fs := flag.NewFlagSet("radar list", flag.ExitOnError)
		configPath := fs.String("config", "", "Path to radar.yaml")
		_ = fs.Parse(cmdArgs)

		cfg, err := radar.LoadConfig(*configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading radar config: %v\n", err)
			os.Exit(1)
		}

		status := "DISABLED (default)"
		if cfg.Settings.Enabled {
			status = "ENABLED"
		}
		fmt.Printf("Radar Status: %s\n", status)
		fmt.Printf("Configured Ecosystem Packs: %s\n\n", strings.Join(cfg.EnabledPacks, ", "))
		if !cfg.Settings.Enabled {
			fmt.Println("Notice: Radar is disabled by default. Pass --enable to sync or set 'settings.enabled: true' in radar.yaml to activate.")
		} else {
			fmt.Println("Active Feeds:")
			for _, f := range cfg.ActiveFeeds() {
				fmt.Printf("  • [%s] %s (Ecosystem: %s, Adapter: %s)\n    URL: %s\n", f.ID, f.Name, f.Ecosystem, f.Adapter, f.URL)
			}
		}

	case "sync":
		fs := flag.NewFlagSet("radar sync", flag.ExitOnError)
		configPath := fs.String("config", "", "Path to radar.yaml")
		dataDir := fs.String("data-dir", "", "Data directory")
		project := fs.String("project", "", "Target project vault")
		enableFlag := fs.Bool("enable", false, "Enable radar for this sync run")
		_ = fs.Parse(cmdArgs)

		cfg, err := radar.LoadConfig(*configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading radar config: %v\n", err)
			os.Exit(1)
		}

		if *enableFlag {
			cfg.Settings.Enabled = true
		}

		if !cfg.Settings.Enabled {
			fmt.Println("Notice: Industry radar live feeds are disabled by default. Running in offline capsule-only ingestion mode.")
			fmt.Println("To enable live external feeds, pass --enable or set 'settings.enabled: true' in radar.yaml.")
		}

		mgr, activeProj, err := initManager(*dataDir, *project)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		defer mgr.Close()

		ctx := context.Background()
		if cfg.Settings.Enabled {
			fmt.Printf("Starting radar sync across %d active feeds into vault %q...\n", len(cfg.ActiveFeeds()), activeProj)
		} else {
			fmt.Printf("Starting offline capsule-only sync into vault %q...\n", activeProj)
		}
		syncer := radar.NewSyncer(cfg, mgr)
		res, err := syncer.SyncPass(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Radar sync failed: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("\n✓ Radar sync completed in %dms\n", res.DurationMillis)
		if len(res.CapsulesChecked) > 0 {
			fmt.Printf("  • Capsules Checked: %d (Ingested Facts: %d)\n", len(res.CapsulesChecked), res.CapsuleIngestedCount)
		}
		if cfg.Settings.Enabled {
			fmt.Printf("  • Total Feeds: %d\n", res.TotalFeeds)
			fmt.Printf("  • Raw Items Fetched: %d\n", res.TotalItems)
		} else {
			fmt.Println("  • Live Feeds: Skipped (radar disabled; offline capsule-only mode)")
		}
		fmt.Printf("  • Total Ingested Facts: %d\n", res.IngestedCount)
		if len(res.Errors) > 0 {
			fmt.Printf("  • Warnings/Errors (%d):\n", len(res.Errors))
			for _, e := range res.Errors {
				fmt.Printf("    - %s\n", e)
			}
		}

	case "export-capsule":
		fs := flag.NewFlagSet("radar export-capsule", flag.ExitOnError)
		dataDir := fs.String("data-dir", "", "Data directory")
		project := fs.String("project", "", "Target project vault")
		outPath := fs.String("out", "radar-baseline.capsule", "Output capsule path")
		_ = fs.Parse(cmdArgs)

		dbPath := getDBPath(*dataDir, *project)
		manifest, err := capsule.ExportCapsule(context.Background(), dbPath, *outPath, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Export failed: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("✓ Successfully exported radar capsule to %s\n", *outPath)
		fmt.Printf("  • Total Records: %d\n", manifest.TotalRecords)
		fmt.Printf("  • SHA-256 Checksum: %s\n", manifest.DBChecksum)

	default:
		fmt.Fprintf(os.Stderr, "Unknown radar action %q. Usage: coppermind radar <sync|detect|list|export-capsule>\n", action)
		os.Exit(1)
	}
}

func runCapsule(args []string) {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: coppermind capsule <keygen|sign|pack|import|list|verify|export> [options]\n")
		os.Exit(1)
	}

	action := args[0]
	cmdArgs := args[1:]

	switch action {
	case "keygen":
		fs := flag.NewFlagSet("capsule keygen", flag.ExitOnError)
		outDir := fs.String("out", "", "Output directory for ed25519.key (0600) and ed25519.pub")
		force := fs.Bool("force", false, "Overwrite existing regular key files (symlinks are always refused)")
		_ = fs.Parse(cmdArgs)

		if strings.TrimSpace(*outDir) == "" {
			fmt.Fprintf(os.Stderr, "Error: --out <dir> is required\nUsage: coppermind capsule keygen --out <dir> [--force]\n")
			os.Exit(1)
		}
		kp, err := capsule.GenerateEd25519Keypair(*outDir, *force)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Keygen REJECTED (fail-closed): %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ Generated local Ed25519 capsule signing keypair\n")
		fmt.Printf("  • Private Key (0600): %s\n", kp.PrivateKeyPath)
		fmt.Printf("  • Public Key  (0644): %s\n", kp.PublicKeyPath)
		fmt.Printf("  • Public Key Hex    : %s\n", kp.PublicKeyHex)

	case "sign":
		fs := flag.NewFlagSet("capsule sign", flag.ExitOnError)
		inPath := fs.String("in", "", "Input Mentor (bonjoski-mentor-v1) or Requirements (bonjoski-requirements-v1) manifest JSON")
		keyPath := fs.String("key", "", "Path to Ed25519 private key file (ed25519.key) or 64-byte hex key")
		outPath := fs.String("out", "", "Output path (.capsule tar.gz archive or signed .json manifest)")
		_ = fs.Parse(cmdArgs)

		if strings.TrimSpace(*inPath) == "" || strings.TrimSpace(*keyPath) == "" {
			fmt.Fprintf(os.Stderr, "Error: --in and --key are required\nUsage: coppermind capsule sign --in <manifest.json> --key <ed25519.key> [--out <signed.capsule>]\n")
			os.Exit(1)
		}
		res, err := capsule.SignCapsuleFile(*inPath, *keyPath, *outPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Capsule sign REJECTED (fail-closed): %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ Signed %s capsule %s@%s (%d items) -> %s\n", res.SchemaVersion, res.Name, res.Version, res.ItemCount, res.OutputPath)
		fmt.Printf("  • Format: %s\n", res.Format)
		fmt.Printf("  • Provenance: %s\n", res.Provenance)
		fmt.Printf("  • Authority Tier: %s\n", res.AuthorityTier)
		fmt.Printf("  • Merkle Root: %s\n", res.MerkleRoot)

	case "pack":
		fs := flag.NewFlagSet("capsule pack", flag.ExitOnError)
		inPath := fs.String("in", "", "Input Mentor or Requirements manifest JSON")
		keyPath := fs.String("key", "", "Optional Ed25519 private key file (ed25519.key) or hex to sign while packing")
		outPath := fs.String("out", "", "Output .capsule tar.gz archive path")
		allowUnsigned := fs.Bool("allow-unsigned", false, "Allow packing an unsigned local draft capsule (tagged TAINT_UNVERIFIED_DRAFT)")
		_ = fs.Parse(cmdArgs)

		if strings.TrimSpace(*inPath) == "" {
			fmt.Fprintf(os.Stderr, "Error: --in is required\nUsage: coppermind capsule pack --in <manifest.json> [--key <ed25519.key>] [--allow-unsigned] [--out <out.capsule>]\n")
			os.Exit(1)
		}
		res, err := capsule.PackCapsuleFile(*inPath, *keyPath, *outPath, *allowUnsigned)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Capsule pack REJECTED (fail-closed): %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ Packed %s capsule %s@%s (%d items) -> %s\n", res.SchemaVersion, res.Name, res.Version, res.ItemCount, res.OutputPath)
		fmt.Printf("  • Provenance: %s\n", res.Provenance)
		fmt.Printf("  • Authority Tier: %s\n", res.AuthorityTier)
		fmt.Printf("  • Merkle Root: %s\n", res.MerkleRoot)

	case "import":
		fs := flag.NewFlagSet("capsule import", flag.ExitOnError)
		dataDir := fs.String("data-dir", "", "Data directory")
		projectName := fs.String("project", "", "Target project vault")
		allowUnsigned := fs.Bool("allow-unsigned", false, "Allow importing an unsigned local draft capsule (tagged TAINT_UNVERIFIED_DRAFT)")
		pubKeySpec := fs.String("pubkey", "", "Optional Ed25519 public key file (ed25519.pub) or hex string to require for signature verification")
		_ = fs.Parse(cmdArgs)

		rest := fs.Args()
		if len(rest) == 0 {
			fmt.Fprintf(os.Stderr, "Error: mentor capsule file path is required\nUsage: coppermind capsule import [--allow-unsigned] [--pubkey <ed25519.pub|hex>] <capsule.mentor.json|.capsule>\n")
			os.Exit(1)
		}
		capsulePath := rest[0]

		var reqPub ed25519.PublicKey
		if strings.TrimSpace(*pubKeySpec) != "" {
			loadedPub, err := capsule.LoadEd25519PublicKey(*pubKeySpec)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: invalid --pubkey: %v\n", err)
				os.Exit(1)
			}
			reqPub = loadedPub
		}

		mgr, activeProj, err := initManager(*dataDir, *projectName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		defer mgr.Close()

		accessor, ok := mgr.Store().(capsule.SQLiteAccessor)
		if !ok {
			fmt.Fprintf(os.Stderr, "Error: mentor capsules require local SQLite WAL storage (COPPERMIND_PROFILE=local)\n")
			os.Exit(1)
		}

		var (
			imported *capsule.ImportedMentorCapsule
		)
		if capsule.DetectCapsuleSchema(capsulePath) == capsule.RequirementsSchemaVersion {
			imported, err = capsule.ImportRequirementsCapsuleFileToStore(context.Background(), accessor, capsulePath, capsule.MentorImportOptions{
				RequiredPubKey: reqPub,
				AllowUnsigned:  *allowUnsigned,
			})
		} else {
			imported, err = capsule.ImportMentorCapsuleFileToStore(context.Background(), accessor, capsulePath, capsule.MentorImportOptions{
				RequiredPubKey: reqPub,
				AllowUnsigned:  *allowUnsigned,
			})
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Mentor capsule import REJECTED (fail-closed): %v\n", err)
			os.Exit(1)
		}

		prefix := imported.MerkleRoot
		if len(prefix) > 12 {
			prefix = prefix[:12]
		}
		fmt.Printf("✓ Imported Security Mentor Capsule %s@%s into vault %q\n", imported.Name, imported.Version, activeProj)
		fmt.Printf("  • Cards: %d\n", imported.CardCount)
		fmt.Printf("  • Authority Tier: %s (advisory; cannot override TIER_0/TIER_1)\n", imported.AuthorityTier)
		fmt.Printf("  • Provenance: %s\n", imported.Provenance)
		fmt.Printf("  • Merkle Root: %s...\n", prefix)

	case "list", "ls":
		fs := flag.NewFlagSet("capsule list", flag.ExitOnError)
		dataDir := fs.String("data-dir", "", "Data directory")
		projectName := fs.String("project", "", "Target project vault")
		_ = fs.Parse(cmdArgs)

		mgr, activeProj, err := initManager(*dataDir, *projectName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		defer mgr.Close()

		accessor, ok := mgr.Store().(capsule.SQLiteAccessor)
		if !ok {
			fmt.Fprintf(os.Stderr, "Error: mentor capsules require local SQLite WAL storage (COPPERMIND_PROFILE=local)\n")
			os.Exit(1)
		}

		caps, err := capsule.ListMentorCapsules(context.Background(), accessor)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error listing mentor capsules: %v\n", err)
			os.Exit(1)
		}
		if len(caps) == 0 {
			fmt.Printf("No custom Security Mentor Capsules imported in vault %q (18 embedded v1.0 mentor cards + 10 PO criteria are active zero-config).\n", activeProj)
			return
		}
		fmt.Printf("Imported Security Mentor Capsules in vault %q (%d):\n", activeProj, len(caps))
		for _, c := range caps {
			prefix := c.MerkleRoot
			if len(prefix) > 12 {
				prefix = prefix[:12]
			}
			fmt.Printf("  • %s@%s (%d cards) [%s | %s | merkle:%s]\n",
				c.Name, c.Version, c.CardCount, c.AuthorityTier, c.Provenance, prefix)
		}

	case "verify":
		fs := flag.NewFlagSet("capsule verify", flag.ExitOnError)
		allowUnsigned := fs.Bool("allow-unsigned", false, "Allow verifying an unsigned local draft capsule")
		pubKeySpec := fs.String("pubkey", "", "Optional Ed25519 public key file (ed25519.pub) or hex string to require for verification")
		_ = fs.Parse(cmdArgs)

		rest := fs.Args()
		if len(rest) == 0 {
			fmt.Fprintf(os.Stderr, "Error: capsule file path is required\nUsage: coppermind capsule verify [--allow-unsigned] [--pubkey <ed25519.pub|hex>] <file>\n")
			os.Exit(1)
		}

		var reqPub ed25519.PublicKey
		if strings.TrimSpace(*pubKeySpec) != "" {
			loadedPub, err := capsule.LoadEd25519PublicKey(*pubKeySpec)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: invalid --pubkey: %v\n", err)
				os.Exit(1)
			}
			reqPub = loadedPub
		}

		ver, err := capsule.VerifyCapsuleFile(rest[0], capsule.MentorImportOptions{
			RequiredPubKey: reqPub,
			AllowUnsigned:  *allowUnsigned,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Verification FAILED (fail-closed): %v\n", err)
			os.Exit(1)
		}
		kindLabel := "Security Mentor Capsule"
		itemLabel := "cards"
		if ver.SchemaVersion == capsule.RequirementsSchemaVersion {
			kindLabel = "Requirements Capsule"
			itemLabel = "criteria"
		}
		fmt.Printf("✓ Verified %s %s@%s (%d %s)\n", kindLabel, ver.Name, ver.Version, ver.ItemCount, itemLabel)
		fmt.Printf("  • Provenance: %s\n", ver.Provenance)
		fmt.Printf("  • Authority Tier: %s\n", ver.AuthorityTier)
		fmt.Printf("  • Merkle Root: %s\n", ver.MerkleRoot)

	case "export":
		fs := flag.NewFlagSet("capsule export", flag.ExitOnError)
		dataDir := fs.String("data-dir", "", "Data directory")
		projectName := fs.String("project", "", "Target project vault")
		name := fs.String("name", "", "Imported mentor capsule name to export from SQLite")
		fromPath := fs.String("from", "", "Optional source .mentor.json path to package/sign into .capsule")
		outPath := fs.String("out", "", "Output path (.capsule or .mentor.json)")
		signKeySpec := fs.String("sign-key", "", "Optional Ed25519 private key file path or 64-byte hex")
		_ = fs.Parse(cmdArgs)

		if *outPath == "" {
			fmt.Fprintf(os.Stderr, "Error: --out is required\nUsage: coppermind capsule export (--name <capsule> | --from <file>) --out <out.capsule>\n")
			os.Exit(1)
		}

		var privKey ed25519.PrivateKey
		if strings.TrimSpace(*signKeySpec) != "" {
			loadedPriv, err := capsule.LoadEd25519PrivateKey(*signKeySpec)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: invalid --sign-key: %v\n", err)
				os.Exit(1)
			}
			privKey = loadedPriv
		}

		var (
			manifest *capsule.MentorCapsuleManifest
			err      error
		)
		if *fromPath != "" {
			manifest, err = capsule.ReadMentorCapsuleFile(*fromPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Export FAILED: %v\n", err)
				os.Exit(1)
			}
		} else if *name != "" {
			mgr, _, initErr := initManager(*dataDir, *projectName)
			if initErr != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", initErr)
				os.Exit(1)
			}
			defer mgr.Close()
			accessor, ok := mgr.Store().(capsule.SQLiteAccessor)
			if !ok {
				fmt.Fprintf(os.Stderr, "Error: mentor capsules require local SQLite WAL storage\n")
				os.Exit(1)
			}
			manifest, err = capsule.GetMentorCapsuleManifestFromStore(context.Background(), accessor, *name)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Export FAILED: %v\n", err)
				os.Exit(1)
			}
		} else {
			fmt.Fprintf(os.Stderr, "Error: either --name or --from is required\n")
			os.Exit(1)
		}

		if strings.HasSuffix(strings.ToLower(*outPath), ".json") {
			err = capsule.ExportMentorCapsuleJSON(manifest, *outPath, privKey)
		} else {
			err = capsule.ExportMentorCapsule(manifest, *outPath, privKey)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Export REJECTED (fail-closed): %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ Exported verified Security Mentor Capsule %s@%s to %s\n", manifest.Name, manifest.Version, *outPath)
		fmt.Printf("  • Merkle Root: %s\n", manifest.MerkleRoot)

	default:
		fmt.Fprintf(os.Stderr, "Unknown capsule action %q. Usage: coppermind capsule <keygen|sign|pack|import|list|verify|export>\n", action)
		os.Exit(1)
	}
}

func runDistill(args []string) {
	fs := flag.NewFlagSet("distill", flag.ExitOnError)
	fromFile := fs.String("from-file", "", "Path to sanitized lesson-to-capsule.md file (bounded 256KB)")
	id := fs.String("id", "", "Kebab-case MentorCard ID slug (e.g. ai-tool-07-negative-refund)")
	domain := fs.String("domain", "", "Domain (deterministic-web | ai-app-rag | mcp-tools | secrets)")
	title := fs.String("title", "", "Plain-English title (<= 120 chars)")
	pattern := fs.String("pattern", "", "What broke (1 generic sentence, zero proprietary info)")
	analogy := fs.String("analogy", "", "Deterministic engineering analogy (<= 160 chars)")
	fix := fs.String("fix", "", "Actionable secure default / 1-line fix-forward pattern (<= 180 chars)")
	why := fs.String("why", "", "Concise 1-sentence reason / impact (<= 200 chars)")
	triggersCSV := fs.String("triggers", "", "Comma-separated keywords/triggers (e.g. refund,mcp,tool)")
	reqTriggersCSV := fs.String("req-triggers", "", "Optional 5-Q trigger flags (auth_data_money,ai_rag_context,ai_state_mutation,supply_chain_mcp,secrets_pii)")
	given := fs.String("given", "", "Optional explicit Given clause for AbuseCaseCriterion")
	when := fs.String("when", "", "Optional explicit When clause for AbuseCaseCriterion")
	then := fs.String("then", "", "Optional explicit Then clause for AbuseCaseCriterion")
	verifyCmd := fs.String("verify-cmd", "", "Allowlisted local bonjoski verify_cmd (e.g. aegisbox test --ai-safety)")
	kataRef := fs.String("kata-ref", "", "Optional local aegisbox kata reference")
	cwe := fs.String("cwe", "", "Optional CWE or OWASP identifier (e.g. OWASP-LLM01)")
	probeCategory := fs.String("probe-category", "", "Optional aegisbox probe category (indirect_prompt_injection, rag_cross_tenant_bleed, tool_arg_path_traversal, tool_arg_ssrf, mcp_scope_escalation, secret_egress_canary)")
	probePayload := fs.String("probe-payload", "", "Optional minimal sanitized reproducer payload")
	expectedSignal := fs.String("expected-signal", "", "Optional expected signal for aegisbox custom probe")
	noProbe := fs.Bool("no-probe", false, "Omit the optional aegisbox custom probe stub")
	outDir := fs.String("out-dir", "", "Optional output directory to write mentor-card, abuse-case, and aegisbox-probe JSON files")
	_ = fs.Parse(args)

	in := capsule.DistillInput{IncludeProbe: !*noProbe}
	if strings.TrimSpace(*fromFile) != "" {
		parsed, err := capsule.ParseLessonMarkdownFile(*fromFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Distill REJECTED (fail-closed): %v\n", err)
			os.Exit(1)
		}
		in = parsed
		in.IncludeProbe = !*noProbe
	}

	if strings.TrimSpace(*id) != "" {
		in.ID = *id
	}
	if strings.TrimSpace(*domain) != "" {
		in.Domain = *domain
	}
	if strings.TrimSpace(*title) != "" {
		in.Title = *title
	}
	if strings.TrimSpace(*pattern) != "" {
		in.Pattern = *pattern
	}
	if strings.TrimSpace(*analogy) != "" {
		in.Analogy = *analogy
	}
	if strings.TrimSpace(*fix) != "" {
		in.Fix = *fix
	}
	if strings.TrimSpace(*why) != "" {
		in.Why = *why
	}
	if strings.TrimSpace(*triggersCSV) != "" {
		var trigs []string
		for _, part := range strings.Split(*triggersCSV, ",") {
			if t := strings.TrimSpace(part); t != "" {
				trigs = append(trigs, t)
			}
		}
		in.Triggers = trigs
	}
	if strings.TrimSpace(*reqTriggersCSV) != "" {
		parsedFlags, err := capsule.ParseTriggerFlags(*reqTriggersCSV)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Distill REJECTED (fail-closed): %v\n", err)
			os.Exit(1)
		}
		in.ReqTriggers = parsedFlags
	}
	if strings.TrimSpace(*given) != "" {
		in.Given = *given
	}
	if strings.TrimSpace(*when) != "" {
		in.When = *when
	}
	if strings.TrimSpace(*then) != "" {
		in.Then = *then
	}
	if strings.TrimSpace(*verifyCmd) != "" {
		in.VerifyCmd = *verifyCmd
	}
	if strings.TrimSpace(*kataRef) != "" {
		in.KataRef = *kataRef
	}
	if strings.TrimSpace(*cwe) != "" {
		in.CWEOrOWASP = *cwe
	}
	if strings.TrimSpace(*probeCategory) != "" {
		in.ProbeCategory = *probeCategory
	}
	if strings.TrimSpace(*probePayload) != "" {
		in.ProbePayload = *probePayload
	}
	if strings.TrimSpace(*expectedSignal) != "" {
		in.ExpectedSignal = *expectedSignal
	}

	res, err := capsule.DistillLesson(in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Distill REJECTED (fail-closed): %v\n", err)
		os.Exit(1)
	}

	if strings.TrimSpace(*outDir) != "" {
		written, err := capsule.WriteDistillArtifacts(*outDir, res)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Distill write FAILED: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ Distilled sanitized lesson %q into flywheel artifacts:\n", res.MentorCard.ID)
		fmt.Printf("  • MentorCard         : %s\n", written.MentorCardPath)
		fmt.Printf("  • AbuseCaseCriterion : %s\n", written.AbuseCasePath)
		if written.ProbeStubPath != "" {
			fmt.Printf("  • Aegisbox Probe Stub: %s\n", written.ProbeStubPath)
		}
		return
	}

	out, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error formatting distill output: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(out))
}

func runRequirements(args []string) {
	fs := flag.NewFlagSet("requirements", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "Data directory")
	projectName := fs.String("project", "", "Target project vault")
	story := fs.String("story", "", "User story or feature description text (ephemeral; never persisted)")
	storyFile := fs.String("story-file", "", "Path to local PRD or story file (strict 256KB cap; ephemeral; never persisted)")
	triggersCSV := fs.String("triggers", "", "Optional comma-separated 5-Q triggers (auth_data_money,ai_rag_context,ai_state_mutation,supply_chain_mcp,secrets_pii)")
	asJSON := fs.Bool("json", false, "Emit machine-readable JSON output")
	includeWhy := fs.Bool("why", false, "Include 1-sentence plain-English business impact and optional kata reference")
	limit := fs.Int("limit", capsule.MaxRequirementsCriteria, "Maximum criteria to return (hard ceiling: 3)")
	_ = fs.Parse(args)

	storyText := strings.TrimSpace(*story)
	if *storyFile != "" {
		fileContent, err := capsule.ReadStoryFileBounded(*storyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading --story-file: %v\n", err)
			os.Exit(1)
		}
		if storyText != "" {
			storyText = storyText + "\n" + fileContent
		} else {
			storyText = fileContent
		}
	}
	if storyText == "" && len(fs.Args()) > 0 {
		storyText = strings.Join(fs.Args(), " ")
	}

	triggers, err := capsule.ParseTriggerFlags(*triggersCSV)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing --triggers: %v\n", err)
		os.Exit(1)
	}

	if strings.TrimSpace(storyText) == "" && len(triggers) == 0 {
		fmt.Fprintf(os.Stderr, "Error: provide --story, --story-file, or --triggers\nUsage: coppermind requirements [--story \"...\"] [--story-file ./prd.md] [--triggers ai_rag_context,ai_state_mutation] [--json] [--why]\n")
		os.Exit(1)
	}

	// Strictly read-only & ephemeral: only open local SQLite if the vault DB already exists
	// (so custom imported requirements capsules are picked up), and NEVER persist storyText.
	var store brain.MemoryStore
	if getProfile() != "cluster" {
		dbPath := getDBPath(*dataDir, *projectName)
		if info, statErr := os.Stat(dbPath); statErr == nil && !info.IsDir() {
			if st, openErr := sqlite.NewSQLiteStore(dbPath); openErr == nil {
				store = st
				defer st.Close()
			}
		}
	}

	reqLens := lenses.NewSQLiteRequirementsLens(store, embedding.NewLocalHashEmbedder(128))
	criteria, err := reqLens.SuggestCriteriaContext(context.Background(), storyText, triggers, *limit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating requirements criteria: %v\n", err)
		os.Exit(1)
	}

	if *asJSON {
		out, err := lenses.FormatRequirementsJSON(criteria, *includeWhy)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error formatting JSON: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(out)
		return
	}

	fmt.Println(lenses.FormatRequirementsMarkdown(criteria, *includeWhy))
}
