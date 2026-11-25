package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/capsule"
	"github.com/bonjoski/coppermind/pkg/embedding"
	"github.com/bonjoski/coppermind/pkg/graph"
	"github.com/bonjoski/coppermind/pkg/lenses"
	"github.com/bonjoski/coppermind/pkg/project"
	"github.com/bonjoski/coppermind/pkg/queue"
	"github.com/bonjoski/coppermind/pkg/scratchpad"
	"github.com/bonjoski/coppermind/pkg/security"
	"github.com/bonjoski/coppermind/pkg/storage"
	"github.com/bonjoski/coppermind/pkg/storage/sqlite"
	"github.com/bonjoski/coppermind/pkg/version"
	"github.com/bonjoski/coppermind/pkg/worker"
)

// Server implements a native Model Context Protocol (MCP) server over STDIO or arbitrary streams.
type Server struct {
	manager          *brain.Manager
	projectMgr       *project.Manager
	mentorLens       *lenses.SQLiteMentorLens
	requirementsLens *lenses.SQLiteRequirementsLens
	lensConfig       *lenses.LensesConfig
	hostEval         *lenses.DefaultHostEvaluator
	broker           queue.Broker
	worker           *worker.CognitiveWorker
	inMu             sync.Mutex
	outMu            sync.Mutex
	writer           io.Writer
	startTime        time.Time
}

// NewServer creates a new MCP server wrapping the brain manager.
func NewServer(manager *brain.Manager, out io.Writer) *Server {
	if out == nil {
		out = os.Stdout
	}
	var ml *lenses.SQLiteMentorLens
	var rl *lenses.SQLiteRequirementsLens
	if manager != nil {
		embedder := embedding.NewLocalHashEmbedder(128)
		ml = lenses.NewSQLiteMentorLens(manager.Store(), embedder)
		rl = lenses.NewSQLiteRequirementsLens(manager.Store(), embedder)
	} else {
		embedder := embedding.NewLocalHashEmbedder(128)
		ml = lenses.NewSQLiteMentorLens(nil, embedder)
		rl = lenses.NewSQLiteRequirementsLens(nil, embedder)
	}
	lensCfg := lenses.DefaultConfig()
	hostEv, _ := lenses.NewDefaultHostEvaluator(manager, "default", lensCfg)
	return &Server{
		manager:          manager,
		projectMgr:       project.NewManager(""),
		mentorLens:       ml,
		requirementsLens: rl,
		lensConfig:       lensCfg,
		hostEval:         hostEv,
		writer:           out,
		startTime:        time.Now(),
	}
}

// SetWorker binds the message broker and background worker.
func (s *Server) SetWorker(broker queue.Broker, w *worker.CognitiveWorker) {
	s.broker = broker
	s.worker = w
}

// ServeSTDIO starts reading JSON-RPC 2.0 messages from in and writing responses to the configured output.
func (s *Server) ServeSTDIO(ctx context.Context, in io.Reader) error {
	return s.ServeStream(ctx, in, s.writer)
}

// ServeStream reads JSON-RPC 2.0 messages from in and writes responses to out.
func (s *Server) ServeStream(ctx context.Context, in io.Reader, out io.Writer) error {
	scanner := bufio.NewScanner(in)
	// Buffer size for handling large tool call payloads
	buf := make([]byte, 1024*1024)
	scanner.Buffer(buf, 10*1024*1024)

	var writeMu sync.Mutex
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}

		var msg JSONRPCMessage
		if err := json.Unmarshal(line, &msg); err != nil {
			errResp := NewErrorResponse(nil, ErrCodeParseError, "Invalid JSON-RPC 2.0 payload")
			data, _ := json.Marshal(errResp)
			writeMu.Lock()
			_, _ = out.Write(append(data, '\n'))
			writeMu.Unlock()
			continue
		}

		resp := s.handleMessage(ctx, &msg)
		if resp != nil {
			data, err := json.Marshal(resp)
			if err != nil {
				return err
			}
			writeMu.Lock()
			_, err = out.Write(append(data, '\n'))
			writeMu.Unlock()
			if err != nil {
				return err
			}
		}
	}
	return scanner.Err()
}

func (s *Server) writeMessage(msg *JSONRPCMessage) error {
	s.outMu.Lock()
	defer s.outMu.Unlock()

	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = s.writer.Write(data)
	return err
}

func (s *Server) handleMessage(ctx context.Context, msg *JSONRPCMessage) *JSONRPCMessage {
	switch msg.Method {
	case "initialize":
		return s.handleInitialize(msg)
	case "notifications/initialized":
		// Per MCP spec, notifications do not return a response
		return nil
	case "tools/list":
		return s.handleToolsList(msg)
	case "tools/call":
		return s.handleToolsCall(ctx, msg)
	case "prompts/list":
		return s.handlePromptsList(msg)
	case "prompts/get":
		return s.handlePromptsGet(ctx, msg)
	case "resources/list":
		return s.handleResourcesList(msg)
	case "resources/read":
		return s.handleResourcesRead(ctx, msg)
	case "ping":
		resp, _ := NewSuccessResponse(msg.ID, map[string]string{"status": "ok"})
		return resp
	default:
		// If ID is null or missing, it's a notification
		if len(msg.ID) == 0 {
			return nil
		}
		return NewErrorResponse(msg.ID, ErrCodeMethodNotFound, fmt.Sprintf("Method %q not supported", msg.Method))
	}
}

func (s *Server) handleInitialize(msg *JSONRPCMessage) *JSONRPCMessage {
	result := map[string]interface{}{
		"protocolVersion": "2024-11-05",
		"serverInfo": map[string]string{
			"name":    "coppermind",
			"version": version.Version,
		},
		"capabilities": map[string]interface{}{
			"tools": map[string]bool{
				"listChanged": false,
			},
			"prompts": map[string]bool{
				"listChanged": false,
			},
			"resources": map[string]bool{
				"subscribe":   false,
				"listChanged": false,
			},
		},
	}
	resp, _ := NewSuccessResponse(msg.ID, result)
	return resp
}

func (s *Server) handleToolsList(msg *JSONRPCMessage) *JSONRPCMessage {
	tools := []ToolDef{
		{
			Name:        "coppermind_remember",
			Description: "Persist an architectural invariant, decision, pattern, or finding into the cognitive brain.",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"content": { "type": "string", "description": "The exact fact, insight, or invariant to remember." },
					"category": { "type": "string", "description": "Category (e.g. architecture, convention, bug_fix, runbook, personal)." },
					"project": { "type": "string", "description": "Optional isolated project vault name (e.g. github, personal, work)." },
					"session_id": { "type": "string", "description": "Optional session/worktree identifier." },
					"provenance": { "type": "string", "enum": ["TRUST_LOCAL_WORKSPACE", "TAINT_EXTERNAL_USER", "TAINT_UNTRUSTED_WEB"] },
					"supersedes": { "type": "string", "description": "Optional UUID of previous memory to supersede and tombstone." },
					"rationale": { "type": "string", "description": "Mandatory rationale when superseding an existing memory." },
					"advisory_ref": { "type": "string", "description": "Optional advisory reference (e.g. ADR-042)." },
					"author_role": { "type": "string", "description": "Optional author role (e.g. architect, product_owner, developer)." }
				},
				"required": ["content"]
			}`),
		},
		{
			Name:        "coppermind_recall",
			Description: "Perform semantic and hybrid search over stored memories in a project vault, optionally filtering by cognitive lens (including lens='mentor' for passive security nudges and lens='requirements' for ephemeral PO abuse-case acceptance criteria) or auto-attaching observations.",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"query": { "type": "string", "description": "Natural language query or ephemeral user story text to search/match." },
					"project": { "type": "string", "description": "Optional isolated project vault name (e.g. github, personal, work)." },
					"category": { "type": "string", "description": "Optional category filter." },
					"session_id": { "type": "string", "description": "Optional session filter." },
					"limit": { "type": "integer", "description": "Max results to return (default 5; hard ceiling 2 for lens='mentor', 3 for lens='requirements')." },
					"min_score": { "type": "number", "description": "Minimum similarity score threshold (default 0.0)." },
					"lens": { "type": "string", "description": "Optional cognitive lens filter (e.g. mentor, requirements, security-architect, systems-architect, drift-auditor, synthesizer)." },
					"detected_sdks": { "type": "array", "items": { "type": "string" }, "description": "Optional detected SDK/framework hints when lens='mentor' (e.g. ['openai', 'mcp', 'pgvector'])." },
					"triggers": { "type": "array", "items": { "type": "string" }, "description": "Optional 5-Q blast-radius trigger flags when lens='requirements' (auth_data_money, ai_rag_context, ai_state_mutation, supply_chain_mcp, secrets_pii)." },
					"include_why": { "type": "boolean", "description": "When lens='requirements', include plain-English 1-sentence business impact and optional kata link (default false)." },
					"include_observations": { "type": "boolean", "description": "Whether to auto-attach linked cognitive lens observations to recalled memories (default true)." },
					"include_superseded": { "type": "boolean", "description": "Whether to include superseded historical memories in results (default false)." },
					"tier": { "type": "string", "description": "Optional authority tier filter (e.g. TIER_1_ARCHITECTURE)." },
					"since": { "type": "string", "description": "Optional lower temporal bound (e.g. 24h, 7d, 30d, YYYY-MM-DD, RFC3339)." },
					"before": { "type": "string", "description": "Optional upper temporal bound (e.g. 24h, 7d, YYYY-MM-DD, RFC3339)." },
					"hops": { "type": "integer", "description": "Optional knowledge graph expansion depth (0, 1, or 2; default 1)." },
					"emit_receipt": { "type": "boolean", "description": "When true and FABRIAL_RECEIPT_DIR is set, atomically emit a BLPR-v1 ideation receipt (signed via LOCKSMITH_SOCKET when reachable)." }
				},
				"required": ["query"]
			}`),
		},
		{
			Name:        "coppermind_project",
			Description: "List, switch, or inspect isolated project vaults (e.g. github, personal, work).",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"action": { "type": "string", "enum": ["list", "use", "create"], "description": "Project action to perform." },
					"name": { "type": "string", "description": "Project name for use or create actions." }
				},
				"required": ["action"]
			}`),
		},
		{
			Name:        "coppermind_scratchpad",
			Description: "Interact with fast working memory (ephemeral key-value state, locks, atomic CAS handoffs, and subagent coordination).",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"action": { "type": "string", "enum": ["get", "set", "cas", "delete", "lock", "keys"] },
					"key": { "type": "string", "description": "Key name." },
					"value": { "type": "string", "description": "Value to set (for 'set' or 'cas' action)." },
					"expected_value": { "type": "string", "description": "Expected current value for atomic 'cas' action (empty string = create-if-absent)." },
					"ttl_seconds": { "type": "integer", "description": "TTL in seconds for set, cas, or lock (default 300)." }
				},
				"required": ["action"]
			}`),
		},
		{
			Name:        "coppermind_status",
			Description: "Inspect cognitive brain metrics, memory counts, and scratchpad state.",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {}
			}`),
		},
		{
			Name:        "coppermind_dispatch_task",
			Description: "Dispatch an asynchronous cognitive workflow onto the RabbitMQ/AMQP message bus (e.g. session reflection, memory defragmentation, or analytical lens reflection).",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"task_type": { "type": "string", "enum": ["summarize_session", "deep_reflect", "defrag_memory", "reflect"], "description": "Type of cognitive task to execute in the background." },
					"session_id": { "type": "string", "description": "Target session/worktree identifier." },
					"payload": { "type": "object", "description": "Optional arbitrary JSON parameters for the task (e.g. {'lens': 'security-architect'})." }
				},
				"required": ["task_type"]
			}`),
		},
		{
			Name:        "coppermind_lens_prepare",
			Description: "Prepare a zero-API-key host-evaluated cognitive lens prompt bundle with AST/regex pre-filtering, secret redaction, sibling-endpoint & ADR recall, XML <untrusted_artifact> fencing, and a single-use HMAC-SHA256 eval_token.",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"lens": { "type": "string", "enum": ["security-architect", "systems-architect", "drift-auditor", "synthesizer", "red-team", "devils-advocate"], "description": "Cognitive lens persona to prepare." },
					"target_id": { "type": "string", "description": "Existing Coppermind memory node ID to inspect." },
					"content": { "type": "string", "description": "Inline candidate code or artifact content to inspect (bounded to 6,000 chars and secret-redacted)." },
					"file_path": { "type": "string", "description": "Optional workspace file path for differential sibling-endpoint retrieval." },
					"project": { "type": "string", "description": "Optional isolated project vault name." },
					"session_id": { "type": "string", "description": "Optional session/worktree identifier cryptographically bound into eval_token." },
					"from_inbox": { "type": "boolean", "description": "When true, automatically pop the oldest pending commit review ticket from the zero-key Pending Lens Inbox." },
					"force": { "type": "boolean", "description": "Bypass zero-cost pre-filter gate even when no sensitive sinks match (default false)." }
				},
				"required": ["lens"]
			}`),
		},
		{
			Name:        "coppermind_lens_submit",
			Description: "Validate a single-use HMAC-SHA256 eval_token and ingest host-evaluated JSON findings through deterministic NFKC/Stormcage quarantine, EnforcePoCGate, SHA-256 deduplication, TIER_3_DERIVED persistence, and optional BLPR-v1 receipt emission.",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"eval_token": { "type": "string", "description": "Single-use HMAC-SHA256 eval_token returned by coppermind_lens_prepare." },
					"findings_json": { "description": "Strict JSON string or object matching {\"findings\": [...]} produced by the host AI model." },
					"project": { "type": "string", "description": "Optional isolated project vault name (must match eval_token project if provided)." },
					"session_id": { "type": "string", "description": "Session/worktree identifier (must match eval_token session_id when token is session-bound)." },
					"emit_receipt": { "type": "boolean", "description": "When true and FABRIAL_RECEIPT_DIR is set, atomically emit a BLPR-v1 receipt (signed via LOCKSMITH_SOCKET when reachable)." }
				},
				"required": ["eval_token", "findings_json"]
			}`),
		},
		{
			Name:        "coppermind_consolidate_prepare",
			Description: "Prepare a zero-API-key Sleep-Cycle memory consolidation bundle of up to 30 unconsolidated TIER_3_EPISODIC memories fenced inside <untrusted_artifact> tags with a single-use HMAC-SHA256 eval_token.",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"project": { "type": "string", "description": "Optional isolated project vault name." },
					"session_id": { "type": "string", "description": "Optional session filter." },
					"max_nodes": { "type": "integer", "description": "Max episodic candidates to bundle (default 30, ceiling 30)." }
				}
			}`),
		},
		{
			Name:        "coppermind_consolidate_submit",
			Description: "Validate a single-use HMAC-SHA256 consolidation eval_token, persist synthesized learnings strictly as PROPOSED/TIER_3_DERIVED, record contradiction graph edges, and supersede ONLY allowlisted TIER_3_EPISODIC candidates.",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"eval_token": { "type": "string", "description": "Single-use HMAC-SHA256 eval_token from coppermind_consolidate_prepare." },
					"consolidation_json": { "description": "Strict JSON object matching {\"learnings\":[...],\"contradictions\":[...]}." },
					"project": { "type": "string", "description": "Optional isolated project vault name." },
					"session_id": { "type": "string", "description": "Optional session identifier." }
				},
				"required": ["eval_token", "consolidation_json"]
			}`),
		},
	}

	resp, _ := NewSuccessResponse(msg.ID, map[string]interface{}{"tools": tools})
	return resp
}

func (s *Server) handleToolsCall(ctx context.Context, msg *JSONRPCMessage) *JSONRPCMessage {
	var params ToolCallParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return NewErrorResponse(msg.ID, ErrCodeInvalidParams, "Invalid tool call parameters")
	}

	var result *ToolCallResult
	var err error

	switch params.Name {
	case "coppermind_remember":
		result, err = s.callRemember(ctx, params.Arguments)
	case "coppermind_recall":
		result, err = s.callRecall(ctx, params.Arguments, params.Meta)
	case "coppermind_project":
		result, err = s.callProject(ctx, params.Arguments)
	case "coppermind_scratchpad":
		result, err = s.callScratchpad(ctx, params.Arguments)
	case "coppermind_dispatch_task":
		result, err = s.callDispatchTask(ctx, params.Arguments)
	case "coppermind_status":
		result, err = s.callStatus(ctx)
	case "coppermind_lens_prepare":
		result, err = s.callLensPrepare(ctx, params.Arguments, params.Meta)
	case "coppermind_lens_submit":
		result, err = s.callLensSubmit(ctx, params.Arguments, params.Meta)
	case "coppermind_consolidate_prepare":
		result, err = s.callConsolidatePrepare(ctx, params.Arguments, params.Meta)
	case "coppermind_consolidate_submit":
		result, err = s.callConsolidateSubmit(ctx, params.Arguments, params.Meta)
	default:
		return NewErrorResponse(msg.ID, ErrCodeMethodNotFound, fmt.Sprintf("Tool %q not found", params.Name))
	}

	if err != nil {
		result = classifyCoppermindError(params.Name, err)
	}

	resp, _ := NewSuccessResponse(msg.ID, result)
	return resp
}

// classifyCoppermindError maps Coppermind quarantine, validation, and policy denials to
// UB-MCP-v1 FixForwardError payloads (exit_code: 10) and general I/O errors to exit_code: 1.
func classifyCoppermindError(toolName string, err error) *ToolCallResult {
	errMsg := SanitizeSingleLine(err.Error())

	switch {
	case errors.Is(err, security.ErrSecretRejected):
		return NewUBMCPv1ErrorResult(FixForwardError{
			Code:           "COPPERMIND_SECRET_QUARANTINE",
			ExitCode:       ExitCodePolicyDeny,
			Retryable:      true,
			Summary:        "Paused memory write: raw credential or private key blocked by secret quarantine.",
			RemediationCmd: "locksmith checkout --secret <name>",
			Why:            "Coppermind never persists raw credentials or private keys in memory vaults; use Locksmith opaque leases instead.",
			References:     []string{"https://github.com/bonjoski/coppermind/blob/main/docs/use-cases/05-episodic-scratchpad-integrity.md"},
		})

	case errors.Is(err, security.ErrPromptInjectionRejected):
		return NewUBMCPv1ErrorResult(FixForwardError{
			Code:           "COPPERMIND_FIREWALL_DENY",
			ExitCode:       ExitCodePolicyDeny,
			Retryable:      false,
			Summary:        "Paused memory write: untrusted input triggered the cognitive firewall.",
			RemediationCmd: "coppermind recall --category quarantined_observations",
			Why:            "Untrusted content containing prompt-injection or delimiter-smuggling directives is blocked to preserve memory integrity.",
			References:     []string{"https://github.com/bonjoski/coppermind/blob/main/docs/use-cases/05-episodic-scratchpad-integrity.md"},
		})

	case errors.Is(err, brain.ErrInvalidAuthorSignature), errors.Is(err, brain.ErrScratchpadIntegrityFail):
		return NewUBMCPv1ErrorResult(FixForwardError{
			Code:           "COPPERMIND_VALIDATION_DENY",
			ExitCode:       ExitCodePolicyDeny,
			Retryable:      true,
			Summary:        "Paused operation: memory validation failed cryptographic integrity verification.",
			RemediationCmd: "coppermind doctor",
			Why:            "Signed memories must verify against their Ed25519 author public key before entering the vault.",
		})

	case errors.Is(err, ErrReceiptPolicyDeny):
		return NewUBMCPv1ErrorResult(FixForwardError{
			Code:           "COPPERMIND_RECEIPT_POLICY_DENY",
			ExitCode:       ExitCodePolicyDeny,
			Retryable:      false,
			Summary:        "Paused receipt emission: FABRIAL_RECEIPT_DIR failed symlink and containment verification.",
			RemediationCmd: "fabrial doctor --fix",
			Why:            "BLPR-v1 receipts must be written atomically inside a real, non-symlinked directory owned by the local user.",
		})

	case errors.Is(err, lenses.ErrEvalTokenInvalid),
		errors.Is(err, lenses.ErrEvalTokenExpired),
		errors.Is(err, lenses.ErrEvalTokenReplayed),
		errors.Is(err, lenses.ErrEvalTokenSessionMismatch):
		return NewUBMCPv1ErrorResult(FixForwardError{
			Code:           "COPPERMIND_EVAL_TOKEN_DENY",
			ExitCode:       ExitCodePolicyDeny,
			Retryable:      false,
			Summary:        fmt.Sprintf("Paused %s: %s", SanitizeSingleLine(toolName), errMsg),
			RemediationCmd: "coppermind_lens_prepare",
			Why:            "Host-evaluated lens submissions require a fresh, unexpired, single-use HMAC-SHA256 eval_token bound to the active session.",
		})

	case errors.Is(err, lenses.ErrInvalidFindingsJSON):
		return NewUBMCPv1ErrorResult(FixForwardError{
			Code:           "COPPERMIND_LENS_INVALID_JSON",
			ExitCode:       ExitCodePolicyDeny,
			Retryable:      true,
			Summary:        fmt.Sprintf("Paused %s: findings_json must be valid JSON matching {\"findings\": [...]}.", SanitizeSingleLine(toolName)),
			RemediationCmd: "coppermind_lens_prepare",
			Why:            "Coppermind only ingests deterministically parsed and PoC-gated JSON findings from host-evaluated lenses.",
		})

	case errors.Is(err, lenses.ErrUnknownLens):
		return NewUBMCPv1ErrorResult(FixForwardError{
			Code:           "COPPERMIND_VALIDATION_DENY",
			ExitCode:       ExitCodePolicyDeny,
			Retryable:      true,
			Summary:        fmt.Sprintf("Paused %s: %s", SanitizeSingleLine(toolName), errMsg),
			RemediationCmd: "coppermind status",
			Why:            "Specify a configured lens such as security-architect, systems-architect, drift-auditor, or synthesizer.",
		})

	case isValidationPolicyError(errMsg):
		summary := fmt.Sprintf("Paused %s: %s", SanitizeSingleLine(toolName), errMsg)
		return NewUBMCPv1ErrorResult(FixForwardError{
			Code:           "COPPERMIND_VALIDATION_DENY",
			ExitCode:       ExitCodePolicyDeny,
			Retryable:      true,
			Summary:        summary,
			RemediationCmd: "coppermind status",
			Why:            "Tool arguments must pass schema, trigger, and policy validation before execution.",
		})

	default:
		summary := fmt.Sprintf("Failed %s: %s", SanitizeSingleLine(toolName), errMsg)
		return NewUBMCPv1ErrorResult(FixForwardError{
			Code:           "COPPERMIND_RUNTIME_ERROR",
			ExitCode:       ExitCodeRuntimeErr,
			Retryable:      true,
			Summary:        summary,
			RemediationCmd: "coppermind doctor",
			Why:            "Coppermind encountered a local runtime error while handling this request.",
		})
	}
}

func isValidationPolicyError(msg string) bool {
	lower := strings.ToLower(msg)
	for _, needle := range []string{
		"invalid arguments",
		"cannot be empty",
		"is required",
		"unknown action",
		"unknown scratchpad action",
		"unknown trigger",
		"unsupported trigger",
		"invalid trigger",
		"policy",
		"quarantine",
		"validation",
		"forbidden",
		"denied",
		"supersession",
	} {
		if strings.Contains(lower, needle) {
			return true
		}
	}
	return false
}

func (s *Server) getManagerForProject(projectName string) (*brain.Manager, func(), error) {
	if projectName == "" || s.projectMgr == nil {
		return s.manager, func() {}, nil
	}

	_, dir, err := s.projectMgr.ResolveProject(projectName)
	if err != nil {
		return nil, nil, err
	}

	dbPath := filepath.Join(dir, "coppermind.db")
	store, err := sqlite.NewSQLiteStore(dbPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open project database: %w", err)
	}

	embedder := embedding.NewEmbedderFromEnv()
	sp := scratchpad.NewMemoryScratchpad()
	mgr := brain.NewManager(store, embedder, sp)

	cleanup := func() {
		_ = mgr.Close()
	}
	return mgr, cleanup, nil
}

func (s *Server) callRemember(ctx context.Context, args json.RawMessage) (*ToolCallResult, error) {
	var input struct {
		Project     string `json:"project"`
		Content     string `json:"content"`
		Category    string `json:"category"`
		SessionID   string `json:"session_id"`
		Provenance  string `json:"provenance"`
		Supersedes  string `json:"supersedes"`
		Rationale   string `json:"rationale"`
		AdvisoryRef string `json:"advisory_ref"`
		AuthorRole  string `json:"author_role"`
		AuthorID    string `json:"author_identity"`
	}
	if err := json.Unmarshal(args, &input); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}

	mgr, cleanup, err := s.getManagerForProject(input.Project)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	prov := brain.ProvenanceLocalWorkspace
	if input.Provenance != "" {
		prov = brain.ProvenanceTier(input.Provenance)
	}

	node, err := mgr.Remember(ctx, brain.RememberRequest{
		SessionID:      input.SessionID,
		Category:       input.Category,
		Content:        input.Content,
		Provenance:     prov,
		SupersedesID:   input.Supersedes,
		Rationale:      input.Rationale,
		AdvisoryRef:    input.AdvisoryRef,
		AuthorRole:     input.AuthorRole,
		AuthorIdentity: input.AuthorID,
	})
	if err != nil {
		return nil, err
	}

	targetProj := input.Project
	if targetProj == "" {
		targetProj = "active"
	}
	msg := fmt.Sprintf("Stored memory %s in vault %q [%s] (%s): %s", node.ID, targetProj, node.Category, node.Provenance, node.Content)
	if node.SupersedesID != "" {
		msg = fmt.Sprintf("Stored memory %s in vault %q (superseded %s, status: %s): %s", node.ID, targetProj, node.SupersedesID, node.LifecycleStatus, node.Content)
	} else if warnings := graph.DetectConflicts(ctx, mgr, node); len(warnings) > 0 {
		msg += fmt.Sprintf("\n⚠ Contradiction Radar: potential conflict with %s (%s, sim=%.2f): %s\n  Tip: %s",
			warnings[0].ConflictingNodeID, warnings[0].AuthorityTier, warnings[0].Similarity, warnings[0].Summary, warnings[0].SuggestedAction)
	}
	return &ToolCallResult{
		Content: []TextContent{{Type: "text", Text: msg}},
	}, nil
}

func (s *Server) callRecall(ctx context.Context, args json.RawMessage, meta *ToolCallMeta) (*ToolCallResult, error) {
	var input struct {
		Project             string   `json:"project"`
		Query               string   `json:"query"`
		Category            string   `json:"category"`
		SessionID           string   `json:"session_id"`
		Limit               int      `json:"limit"`
		MinScore            float32  `json:"min_score"`
		Lens                string   `json:"lens"`
		DetectedSDKs        []string `json:"detected_sdks"`
		Triggers            []string `json:"triggers"`
		IncludeWhy          bool     `json:"include_why"`
		IncludeObservations *bool    `json:"include_observations"`
		IncludeSuperseded   bool     `json:"include_superseded"`
		Tier                string   `json:"tier"`
		Since               string   `json:"since"`
		Before              string   `json:"before"`
		Hops                *int     `json:"hops"`
		EmitReceipt         bool     `json:"emit_receipt"`
	}
	if err := json.Unmarshal(args, &input); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}

	mgr, cleanup, err := s.getManagerForProject(input.Project)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	effectiveSessionID := strings.TrimSpace(input.SessionID)
	var conjoinerSIRID string
	if meta != nil {
		if effectiveSessionID == "" {
			if meta.FabrialSessionID != "" {
				effectiveSessionID = meta.FabrialSessionID
			} else if meta.SessionID != "" {
				effectiveSessionID = meta.SessionID
			}
		}
		conjoinerSIRID = meta.ConjoinerSIRID
	}

	maybeEmitReceipt := func(lensName string, resultsCount int) (any, error) {
		if !input.EmitReceipt {
			return nil, nil
		}
		openHigh := countOpenHighObservations(ctx, mgr)
		emitted, rErr := EmitIdeationReceipt(ctx, IdeationReceiptInput{
			SessionID:            effectiveSessionID,
			ConjoinerSIRID:       conjoinerSIRID,
			Lens:                 lensName,
			Query:                input.Query,
			ResultsCount:         resultsCount,
			OpenHighObservations: openHigh,
		})
		if rErr != nil {
			return nil, rErr
		}
		if emitted == nil {
			return nil, nil
		}
		return map[string]any{
			"receipt_id":             emitted.ReceiptID,
			"receipt_path":           emitted.FilePath,
			"session_id":             emitted.SessionID,
			"signed":                 emitted.Signed,
			"lens":                   lensName,
			"results_count":          resultsCount,
			"open_high_observations": openHigh,
		}, nil
	}

	// Fast-path: Mentor Cognitive Lens (sub-5ms lock-free WAL read, hard ceiling 2 cards, <=120 tokens/nudge)
	if strings.EqualFold(strings.TrimSpace(input.Lens), "mentor") {
		mentorLens := s.mentorLens
		if input.Project != "" || mentorLens == nil {
			var st brain.MemoryStore
			if mgr != nil {
				st = mgr.Store()
			}
			mentorLens = lenses.NewSQLiteMentorLens(st, embedding.NewLocalHashEmbedder(128))
		}
		nudges, err := mentorLens.MatchContext(ctx, input.Query, input.DetectedSDKs, input.Limit)
		if err != nil {
			return nil, err
		}
		sc, err := maybeEmitReceipt("mentor", len(nudges))
		if err != nil {
			return nil, err
		}
		if len(nudges) == 0 {
			return &ToolCallResult{
				Content:           []TextContent{{Type: "text", Text: "No matching security mentor nudges found. Import capsules with `coppermind capsule import <file>`."}},
				StructuredContent: sc,
			}, nil
		}
		return &ToolCallResult{
			Content:           []TextContent{{Type: "text", Text: lenses.FormatMentorNudges(nudges)}},
			StructuredContent: sc,
		}, nil
	}

	// Fast-path: PO & Requirements Cognitive Lens (sub-5ms ephemeral read-only, max 3 criteria, <=180 tokens)
	if strings.EqualFold(strings.TrimSpace(input.Lens), "requirements") || strings.EqualFold(strings.TrimSpace(input.Lens), "po-mentor") {
		reqLens := s.requirementsLens
		if input.Project != "" || reqLens == nil {
			var st brain.MemoryStore
			if mgr != nil {
				st = mgr.Store()
			}
			reqLens = lenses.NewSQLiteRequirementsLens(st, embedding.NewLocalHashEmbedder(128))
		}
		triggers := make([]capsule.TriggerFlag, 0, len(input.Triggers))
		for _, t := range input.Triggers {
			parsed, parseErr := capsule.ParseTriggerFlags(SanitizeSingleLine(t))
			if parseErr != nil {
				return nil, parseErr
			}
			triggers = append(triggers, parsed...)
		}
		criteria, err := reqLens.SuggestCriteriaContext(ctx, input.Query, triggers, input.Limit)
		if err != nil {
			return nil, err
		}
		sc, err := maybeEmitReceipt("requirements", len(criteria))
		if err != nil {
			return nil, err
		}
		return &ToolCallResult{
			Content:           []TextContent{{Type: "text", Text: lenses.FormatRequirementsMarkdown(criteria, input.IncludeWhy)}},
			StructuredContent: sc,
		}, nil
	}

	if input.Limit <= 0 {
		input.Limit = 5
	}

	includeObs := true
	if input.IncludeObservations != nil {
		includeObs = *input.IncludeObservations
	}

	var createdAfter, createdBefore *time.Time
	if strings.TrimSpace(input.Since) != "" {
		t, pErr := brain.ResolveTemporalBound(input.Since, "", time.Now().UTC())
		if pErr != nil {
			return nil, fmt.Errorf("validation failed: %w", pErr)
		}
		createdAfter = &t
	}
	if strings.TrimSpace(input.Before) != "" {
		t, pErr := brain.ResolveTemporalBound(input.Before, "", time.Now().UTC())
		if pErr != nil {
			return nil, fmt.Errorf("validation failed: %w", pErr)
		}
		createdBefore = &t
	}
	hops := 1
	if input.Hops != nil {
		hops = *input.Hops
		if hops < 0 {
			hops = 0
		} else if hops > 2 {
			hops = 2
		}
	}

	results, err := mgr.Recall(ctx, brain.RecallRequest{
		SessionID:           input.SessionID,
		Category:            input.Category,
		Query:               input.Query,
		Limit:               input.Limit,
		MinScore:            input.MinScore,
		Hybrid:              true,
		SourceLens:          input.Lens,
		IncludeObservations: includeObs,
		IncludeSuperseded:   input.IncludeSuperseded,
		AuthorityTier:       input.Tier,
		CreatedAfter:        createdAfter,
		CreatedBefore:       createdBefore,
		Hops:                hops,
	})
	if err != nil {
		return nil, err
	}

	lensTag := strings.TrimSpace(input.Lens)
	if lensTag == "" {
		lensTag = "hybrid"
	}
	sc, err := maybeEmitReceipt(lensTag, len(results))
	if err != nil {
		return nil, err
	}

	if len(results) == 0 {
		return &ToolCallResult{
			Content:           []TextContent{{Type: "text", Text: "No matching memories found."}},
			StructuredContent: sc,
		}, nil
	}

	targetProj := input.Project
	if targetProj == "" {
		targetProj = "active"
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Found %d relevant memories in project vault %q:\n\n", len(results), targetProj))
	for i, r := range results {
		isLearning := r.Node.Category == "learning" ||
			r.Node.Category == "architectural-learning" ||
			r.Node.Category == "lesson" ||
			r.Node.Category == "learnings" ||
			strings.Contains(r.Node.Content, "[ARCHITECTURAL LEARNING") ||
			strings.Contains(r.Node.Content, "**Remediation:**") ||
			strings.Contains(r.Node.Content, "**remediation:**")

		tierBadge := r.Node.AuthorityTier
		if tierBadge == "" {
			tierBadge = "TIER_3_EPISODIC"
		}
		catBadge := r.Node.Category
		if isLearning && !strings.Contains(catBadge, "learning") {
			catBadge = catBadge + " (learning)"
		}

		sb.WriteString(fmt.Sprintf("%d. [Score: %.3f] [%s | %s | %s]\n",
			i+1, r.Score, tierBadge, catBadge, r.Node.Provenance))
		if len(r.GraphLinks) > 0 {
			sb.WriteString(fmt.Sprintf("   [linked via: %s]\n", strings.Join(r.GraphLinks, ", ")))
		}
		if isLearning {
			sb.WriteString("   💡 ARCHITECTURAL LEARNING / INVARIANT:\n")
		}
		sb.WriteString(fmt.Sprintf("   %s\n", r.Node.Content))
		if len(r.Observations) > 0 {
			synthesizerObs := 0
			for _, obs := range r.Observations {
				if obs.SourceLens == "synthesizer" {
					synthesizerObs++
				}
			}
			if synthesizerObs > 0 {
				sb.WriteString(fmt.Sprintf("   ↳ Synthesized Architectural Learnings (%d):\n", synthesizerObs))
			} else {
				sb.WriteString(fmt.Sprintf("   ↳ Linked Observations (%d):\n", len(r.Observations)))
			}
			for _, obs := range r.Observations {
				sb.WriteString(fmt.Sprintf("     • [%s] (%s): %s\n",
					strings.ToUpper(obs.Severity), obs.SourceLens, obs.Content))
			}
		}
		sb.WriteString("\n")
	}

	return &ToolCallResult{
		Content:           []TextContent{{Type: "text", Text: strings.TrimSpace(sb.String())}},
		StructuredContent: sc,
	}, nil
}

func countOpenHighObservations(ctx context.Context, mgr *brain.Manager) int {
	if mgr == nil || mgr.Store() == nil {
		return 0
	}
	obs, err := mgr.ListObservations(ctx, "", "", "open", "high", 1000)
	if err != nil {
		return 0
	}
	return len(obs)
}

func (s *Server) callProject(ctx context.Context, args json.RawMessage) (*ToolCallResult, error) {
	var input struct {
		Action string `json:"action"`
		Name   string `json:"name"`
	}
	if err := json.Unmarshal(args, &input); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}

	if s.projectMgr == nil {
		return nil, fmt.Errorf("project manager not available")
	}

	switch input.Action {
	case "list":
		projects, err := s.projectMgr.ListProjects()
		if err != nil {
			return nil, err
		}
		var sb strings.Builder
		sb.WriteString("Available Project Vaults:\n")
		for _, p := range projects {
			mark := " "
			if p.IsActive {
				mark = "*"
			}
			sb.WriteString(fmt.Sprintf("%s %-12s [%s]\n", mark, p.Name, p.DBPath))
		}
		return &ToolCallResult{
			Content: []TextContent{{Type: "text", Text: strings.TrimSpace(sb.String())}},
		}, nil
	case "use", "switch":
		if input.Name == "" {
			return nil, fmt.Errorf("name is required for 'use' action")
		}
		if err := s.projectMgr.SetCurrentProject(input.Name); err != nil {
			return nil, err
		}
		return &ToolCallResult{
			Content: []TextContent{{Type: "text", Text: fmt.Sprintf("Switched active project vault to %q", input.Name)}},
		}, nil
	case "create":
		if input.Name == "" {
			return nil, fmt.Errorf("name is required for 'create' action")
		}
		p, err := s.projectMgr.CreateProject(input.Name)
		if err != nil {
			return nil, err
		}
		return &ToolCallResult{
			Content: []TextContent{{Type: "text", Text: fmt.Sprintf("Created isolated project vault %q at %s", p.Name, p.DataDir)}},
		}, nil
	default:
		return nil, fmt.Errorf("unknown action %q: must be list, use, or create", input.Action)
	}
}

func (s *Server) callScratchpad(ctx context.Context, args json.RawMessage) (*ToolCallResult, error) {
	var input struct {
		Action        string `json:"action"`
		Key           string `json:"key"`
		Value         string `json:"value"`
		ExpectedValue string `json:"expected_value"`
		TTLSeconds    int    `json:"ttl_seconds"`
	}
	if err := json.Unmarshal(args, &input); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}

	sp := s.manager.Scratchpad()
	var text string

	switch input.Action {
	case "get":
		val, ok := sp.Get(ctx, input.Key)
		if !ok {
			text = fmt.Sprintf("Key %q not found or expired", input.Key)
		} else {
			text = val
		}
	case "set":
		ttl := time.Duration(input.TTLSeconds) * time.Second
		if err := sp.Set(ctx, input.Key, input.Value, ttl); err != nil {
			return nil, err
		}
		text = fmt.Sprintf("Set %q successfully", input.Key)
	case "cas":
		ttl := time.Duration(input.TTLSeconds) * time.Second
		casSp, ok := sp.(scratchpad.CASScratchpad)
		if !ok {
			return nil, fmt.Errorf("scratchpad backend does not support atomic CAS")
		}
		swapped, err := casSp.CompareAndSwap(ctx, input.Key, input.ExpectedValue, input.Value, ttl)
		if err != nil {
			return nil, err
		}
		if swapped {
			text = fmt.Sprintf("CAS succeeded: updated %q atomically", input.Key)
		} else {
			text = fmt.Sprintf("CAS conflict: current value of %q did not match expected_value", input.Key)
		}
	case "delete":
		if err := sp.Delete(ctx, input.Key); err != nil {
			return nil, err
		}
		text = fmt.Sprintf("Deleted %q", input.Key)
	case "lock":
		ttl := time.Duration(input.TTLSeconds) * time.Second
		if ttl <= 0 {
			ttl = 60 * time.Second
		}
		_, err := sp.AcquireLock(ctx, input.Key, ttl)
		if err != nil {
			return nil, err
		}
		text = fmt.Sprintf("Acquired lock on %q for %v", input.Key, ttl)
	case "keys":
		keys := sp.Keys(ctx)
		text = fmt.Sprintf("Active scratchpad keys (%d): %s", len(keys), strings.Join(keys, ", "))
	default:
		return nil, fmt.Errorf("unknown scratchpad action %q", input.Action)
	}

	return &ToolCallResult{
		Content: []TextContent{{Type: "text", Text: text}},
	}, nil
}

func (s *Server) callDispatchTask(ctx context.Context, args json.RawMessage) (*ToolCallResult, error) {
	if s.broker == nil {
		return nil, fmt.Errorf("task broker is not active in this session")
	}

	var input struct {
		TaskType  string                 `json:"task_type"`
		SessionID string                 `json:"session_id"`
		Payload   map[string]interface{} `json:"payload"`
	}
	if err := json.Unmarshal(args, &input); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}

	if input.TaskType == "" {
		return nil, fmt.Errorf("task_type is required")
	}
	if input.SessionID == "" {
		input.SessionID = "default"
	}

	task := &queue.TaskEnvelope{
		SessionID: input.SessionID,
		Type:      queue.TaskType(input.TaskType),
		Payload:   input.Payload,
	}

	topic := fmt.Sprintf("tasks.%s", input.TaskType)
	if err := s.broker.Publish(ctx, topic, task); err != nil {
		return nil, fmt.Errorf("failed to dispatch task: %w", err)
	}

	msg := fmt.Sprintf("✓ Dispatched task [%s] of type %q for session %q onto message bus",
		task.ID, task.Type, task.SessionID)
	return &ToolCallResult{
		Content: []TextContent{{Type: "text", Text: msg}},
	}, nil
}

func (s *Server) callStatus(ctx context.Context) (*ToolCallResult, error) {
	totalMemories, err := s.manager.Count(ctx, "")
	if err != nil {
		return nil, err
	}
	keys := s.manager.Scratchpad().Keys(ctx)

	workerStatus := "Inactive"
	if s.worker != nil {
		metrics := s.worker.Metrics()
		workerStatus = fmt.Sprintf("Active (Processed: %d, Failed: %d)", metrics.TasksProcessed, metrics.TasksFailed)
	}

	status := fmt.Sprintf(
		"Coppermind Cognitive Brain Status:\n"+
			"• Total Stored Memories: %d\n"+
			"• Active Scratchpad Keys: %d\n"+
			"• Cognitive Task Worker: %s\n"+
			"• Uptime: %s\n"+
			"• Protocol: MCP JSON-RPC 2.0 (STDIO / SSE)\n"+
			"• Storage Engine: Pure-Go SQLite WAL Mode + L2 Cosine Vector Index",
		totalMemories,
		len(keys),
		workerStatus,
		time.Since(s.startTime).Round(time.Second),
	)

	return &ToolCallResult{
		Content: []TextContent{{Type: "text", Text: status}},
	}, nil
}

type canonicalPromptSpec struct {
	Def      PromptDef
	LensName string
	Focus    string
}

var canonicalPrompts = []canonicalPromptSpec{
	{
		Def: PromptDef{
			Name:        "coppermind:security-audit",
			Description: "Lean 3-step differential authorization & reproducible PoC threat-model audit using your active AI session (zero extra API keys).",
			Arguments: []PromptArgument{
				{Name: "target_id", Description: "Optional existing Coppermind memory node ID to audit.", Required: false},
				{Name: "file_path", Description: "Optional workspace file path for differential sibling-endpoint recall.", Required: false},
				{Name: "content", Description: "Optional inline code or artifact content to audit directly.", Required: false},
				{Name: "project", Description: "Optional isolated project vault name.", Required: false},
			},
		},
		LensName: "security-architect",
		Focus:    "differential authorization checks, untrusted data flows, and reproducible PoC verification",
	},
	{
		Def: PromptDef{
			Name:        "coppermind:systems-audit",
			Description: "Hop-Tax, N=8 multi-agent concurrency, boundary leak, and lock-contention systems architecture audit (zero extra API keys).",
			Arguments: []PromptArgument{
				{Name: "target_id", Description: "Optional existing Coppermind memory node ID to audit.", Required: false},
				{Name: "file_path", Description: "Optional workspace file path for architectural context recall.", Required: false},
				{Name: "content", Description: "Optional inline code or architecture proposal content to audit directly.", Required: false},
				{Name: "project", Description: "Optional isolated project vault name.", Required: false},
			},
		},
		LensName: "systems-architect",
		Focus:    "Hop-Tax overhead, N=8 multi-agent concurrency contention, layer leaks, and ADR boundaries",
	},
	{
		Def: PromptDef{
			Name:        "coppermind:drift-audit",
			Description: "Implementation vs. stored TIER_0/TIER_1 ADR and convention drift audit (zero extra API keys).",
			Arguments: []PromptArgument{
				{Name: "target_id", Description: "Optional existing Coppermind memory node ID to audit.", Required: false},
				{Name: "file_path", Description: "Optional workspace file path to inspect for ADR drift.", Required: false},
				{Name: "content", Description: "Optional inline diff, code, or documentation content to audit directly.", Required: false},
				{Name: "project", Description: "Optional isolated project vault name.", Required: false},
			},
		},
		LensName: "drift-auditor",
		Focus:    "contradictions with stored TIER_0/TIER_1 ADRs, superseded conventions, and stale documentation",
	},
	{
		Def: PromptDef{
			Name:        "coppermind:consolidate",
			Description: "Zero-API-key Sleep-Cycle memory consolidation distilling noisy episodic notes into PROPOSED learnings and flagging contradictions.",
			Arguments: []PromptArgument{
				{Name: "session_id", Description: "Optional session identifier to consolidate.", Required: false},
				{Name: "project", Description: "Optional isolated project vault name.", Required: false},
			},
		},
		LensName: "consolidator",
		Focus:    "distilling noisy episodic logs into crisp durable learnings and detecting contradictions",
	},
}

func (s *Server) handlePromptsList(msg *JSONRPCMessage) *JSONRPCMessage {
	prompts := make([]PromptDef, 0, len(canonicalPrompts))
	for _, spec := range canonicalPrompts {
		prompts = append(prompts, spec.Def)
	}
	resp, _ := NewSuccessResponse(msg.ID, map[string]interface{}{"prompts": prompts})
	return resp
}

func (s *Server) handlePromptsGet(ctx context.Context, msg *JSONRPCMessage) *JSONRPCMessage {
	var params PromptGetParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return NewErrorResponse(msg.ID, ErrCodeInvalidParams, "Invalid prompts/get parameters")
	}
	name := strings.TrimSpace(params.Name)
	var matched *canonicalPromptSpec
	for i := range canonicalPrompts {
		if canonicalPrompts[i].Def.Name == name {
			matched = &canonicalPrompts[i]
			break
		}
	}
	if matched == nil {
		return NewErrorResponse(msg.ID, ErrCodeInvalidParams, fmt.Sprintf("Unknown prompt %q", name))
	}

	targetID := strings.TrimSpace(params.Arguments["target_id"])
	filePath := strings.TrimSpace(params.Arguments["file_path"])
	content := params.Arguments["content"]
	projectName := strings.TrimSpace(params.Arguments["project"])

	var messageText string
	if matched.LensName == "consolidator" {
		messageText = "Execute Coppermind zero-API-key Sleep-Cycle consolidation:\n" +
			"1. Call MCP tool `coppermind_consolidate_prepare`.\n" +
			"2. If `skipped` is true, report that no unconsolidated episodic memories are pending.\n" +
			"3. Otherwise distill up to 5 crisp durable learnings and identify contradictions from the fenced `<untrusted_artifact>` batch.\n" +
			"4. Call `coppermind_consolidate_submit` with `eval_token` and your strict JSON payload so Coppermind enforces TIER_0/1/2 immutability and stores PROPOSED learnings."
	} else if targetID != "" || strings.TrimSpace(content) != "" {
		bundle, err := s.prepareLensBundle(ctx, lensPrepareInput{
			Lens:     matched.LensName,
			TargetID: targetID,
			Content:  content,
			FilePath: filePath,
			Project:  projectName,
			Force:    true,
		}, nil)
		if err != nil {
			return NewErrorResponse(msg.ID, ErrCodeInvalidParams, SanitizeSingleLine(err.Error()))
		}
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("Run Coppermind zero-API-key %s audit (%s).\n\n", matched.Def.Name, matched.Focus))
		sb.WriteString(bundle.SystemPrompt)
		sb.WriteString("\n\n")
		sb.WriteString(bundle.UserPrompt)
		sb.WriteString(fmt.Sprintf("\n\nAfter producing strict JSON matching %s, call tool %q with eval_token=%q and your JSON in findings_json.",
			bundle.OutputSchema, bundle.SubmitTool, bundle.EvalToken))
		messageText = sb.String()
	} else {
		var argHints []string
		argHints = append(argHints, fmt.Sprintf(`"lens": %q`, matched.LensName))
		if filePath != "" {
			argHints = append(argHints, fmt.Sprintf(`"file_path": %q`, filePath))
		}
		if projectName != "" {
			argHints = append(argHints, fmt.Sprintf(`"project": %q`, projectName))
		}
		messageText = fmt.Sprintf(
			"Execute Coppermind zero-API-key %s (%s) using your active session:\n"+
				"1. Call MCP tool `coppermind_lens_prepare` with {%s} plus either `content` (the code/diff under review) or `target_id`.\n"+
				"2. If `skipped` is true, report that the zero-cost pre-filter found no sensitive sinks and stop.\n"+
				"3. Otherwise evaluate the fenced `<untrusted_artifact>` strictly according to `system_prompt` and `user_prompt`, outputting valid JSON matching `output_schema`.\n"+
				"4. Submit the JSON findings and `eval_token` to `coppermind_lens_submit` so Coppermind enforces NFKC/Stormcage quarantine, PoC gating, SHA-256 deduplication, and TIER_3_DERIVED storage.",
			matched.Def.Name, matched.Focus, strings.Join(argHints, ", "),
		)
	}

	result := PromptGetResult{
		Description: matched.Def.Description,
		Messages: []PromptMessage{
			{
				Role: "user",
				Content: TextContent{
					Type: "text",
					Text: messageText,
				},
			},
		},
	}
	resp, _ := NewSuccessResponse(msg.ID, result)
	return resp
}

type lensPrepareInput struct {
	Lens      string `json:"lens"`
	TargetID  string `json:"target_id"`
	Content   string `json:"content"`
	FilePath  string `json:"file_path"`
	Project   string `json:"project"`
	SessionID string `json:"session_id"`
	FromInbox bool   `json:"from_inbox"`
	Force     bool   `json:"force"`
}

func (s *Server) prepareLensBundle(ctx context.Context, input lensPrepareInput, meta *ToolCallMeta) (*lenses.PreparedLensBundle, error) {
	if s.hostEval == nil {
		return nil, fmt.Errorf("host evaluator is not initialized")
	}

	lensName := strings.TrimSpace(input.Lens)
	if lensName == "" {
		return nil, fmt.Errorf("%w: lens is required", lenses.ErrUnknownLens)
	}
	lensCfg, ok := s.lensConfig.GetLens(lensName)
	if !ok {
		return nil, fmt.Errorf("%w: %q", lenses.ErrUnknownLens, lensName)
	}

	mgr, cleanup, err := s.getManagerForProject(input.Project)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	targetID := strings.TrimSpace(input.TargetID)
	if input.FromInbox && targetID == "" && strings.TrimSpace(input.Content) == "" {
		if inboxStore, ok := mgr.Store().(storage.InboxStore); ok {
			tkt, pErr := inboxStore.PeekOldestPendingTicket(ctx, lensName)
			if pErr != nil {
				return nil, pErr
			}
			if tkt == nil {
				return &lenses.PreparedLensBundle{
					Skipped:    true,
					SkipReason: "inbox_empty",
					LensName:   lensName,
				}, nil
			}
			targetID = tkt.MemoryID
			input.Force = true // Commit already matched pre-filter when queued
		}
	}

	if targetID == "" && strings.TrimSpace(input.Content) == "" {
		return nil, fmt.Errorf("invalid arguments: either target_id, content, or from_inbox=true is required")
	}

	effectiveSessionID := strings.TrimSpace(input.SessionID)
	if effectiveSessionID == "" && meta != nil {
		if meta.FabrialSessionID != "" {
			effectiveSessionID = strings.TrimSpace(meta.FabrialSessionID)
		} else if meta.SessionID != "" {
			effectiveSessionID = strings.TrimSpace(meta.SessionID)
		}
	}

	var candidate *brain.MemoryNode
	if targetID != "" {
		if mgr == nil || mgr.Store() == nil {
			return nil, fmt.Errorf("memory store not available for target_id lookup")
		}
		node, getErr := mgr.Store().GetByID(ctx, targetID)
		if getErr != nil || node == nil {
			return nil, fmt.Errorf("validation failed: target_id %q not found", targetID)
		}
		cp := *node
		if cp.Metadata != nil {
			metaCopy := make(map[string]string, len(cp.Metadata)+1)
			for k, v := range cp.Metadata {
				metaCopy[k] = v
			}
			cp.Metadata = metaCopy
		}
		if strings.TrimSpace(input.FilePath) != "" {
			if cp.Metadata == nil {
				cp.Metadata = make(map[string]string)
			}
			cp.Metadata["file_path"] = strings.TrimSpace(input.FilePath)
		}
		if effectiveSessionID != "" {
			cp.SessionID = effectiveSessionID
		}
		candidate = &cp
	} else {
		var nodeMeta map[string]string
		if fp := strings.TrimSpace(input.FilePath); fp != "" {
			nodeMeta = map[string]string{"file_path": fp}
		}
		candidate = &brain.MemoryNode{
			SessionID:  effectiveSessionID,
			Category:   "code",
			Content:    input.Content,
			Provenance: brain.ProvenanceLocalWorkspace,
			Metadata:   nodeMeta,
			CreatedAt:  time.Now().UTC(),
		}
	}

	projName := strings.TrimSpace(input.Project)
	if projName == "" {
		projName = "default"
	}

	return s.hostEval.PrepareWithManager(ctx, mgr, projName, lensCfg, candidate, input.Force)
}

func (s *Server) callLensPrepare(ctx context.Context, args json.RawMessage, meta *ToolCallMeta) (*ToolCallResult, error) {
	var input lensPrepareInput
	if err := json.Unmarshal(args, &input); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}

	bundle, err := s.prepareLensBundle(ctx, input, meta)
	if err != nil {
		return nil, err
	}

	raw, err := json.Marshal(bundle)
	if err != nil {
		return nil, fmt.Errorf("failed marshaling prepared lens bundle: %w", err)
	}

	return &ToolCallResult{
		Content:           []TextContent{{Type: "text", Text: string(raw)}},
		StructuredContent: bundle,
	}, nil
}

func (s *Server) callLensSubmit(ctx context.Context, args json.RawMessage, meta *ToolCallMeta) (*ToolCallResult, error) {
	if s.hostEval == nil {
		return nil, fmt.Errorf("host evaluator is not initialized")
	}

	var input struct {
		EvalToken    string          `json:"eval_token"`
		FindingsJSON json.RawMessage `json:"findings_json"`
		Project      string          `json:"project"`
		SessionID    string          `json:"session_id"`
		EmitReceipt  bool            `json:"emit_receipt"`
	}
	if err := json.Unmarshal(args, &input); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}

	if strings.TrimSpace(input.EvalToken) == "" {
		return nil, lenses.ErrEvalTokenInvalid
	}

	rawFindings, err := decodeFindingsJSONArg(input.FindingsJSON)
	if err != nil {
		return nil, err
	}

	effectiveSessionID := strings.TrimSpace(input.SessionID)
	var conjoinerSIRID string
	if meta != nil {
		if effectiveSessionID == "" {
			if meta.FabrialSessionID != "" {
				effectiveSessionID = strings.TrimSpace(meta.FabrialSessionID)
			} else if meta.SessionID != "" {
				effectiveSessionID = strings.TrimSpace(meta.SessionID)
			}
		}
		conjoinerSIRID = meta.ConjoinerSIRID
	}

	// Verify token claims up front (without consuming replay) to resolve isolated project vault safely.
	claims, err := s.hostEval.VerifyTokenClaims(input.EvalToken)
	if err != nil {
		return nil, err
	}

	targetProject := strings.TrimSpace(input.Project)
	if targetProject != "" && claims.Project != "" && targetProject != claims.Project {
		return nil, fmt.Errorf("%w: project mismatch", lenses.ErrEvalTokenInvalid)
	}
	projectForMgr := targetProject
	if projectForMgr == "" && claims.Project != "" && claims.Project != "default" {
		projectForMgr = claims.Project
	}

	mgr, cleanup, err := s.getManagerForProject(projectForMgr)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	subRes, err := s.hostEval.SubmitWithManager(ctx, mgr, input.EvalToken, rawFindings, effectiveSessionID)
	if err != nil {
		return nil, err
	}

	// Atomically close any matching pending inbox ticket for (lens, target_id)
	if claims.TargetID != "" {
		if inboxStore, ok := mgr.Store().(storage.InboxStore); ok {
			_ = inboxStore.ResolvePendingTicketsByMemory(ctx, claims.LensName, claims.TargetID)
		}
	}

	if input.EmitReceipt {
		receiptSession := effectiveSessionID
		if receiptSession == "" {
			receiptSession = claims.SessionID
		}
		openHigh := countOpenHighObservations(ctx, mgr)
		emitted, rErr := EmitIdeationReceipt(ctx, IdeationReceiptInput{
			SessionID:            receiptSession,
			ConjoinerSIRID:       conjoinerSIRID,
			Lens:                 subRes.LensName,
			Query:                fmt.Sprintf("host_eval:%s:%s", subRes.LensName, claims.TargetSHA256),
			ResultsCount:         subRes.AcceptedCount,
			OpenHighObservations: openHigh,
		})
		if rErr != nil {
			return nil, rErr
		}
		if emitted != nil {
			subRes.ReceiptID = emitted.ReceiptID
		}
	}

	raw, err := json.Marshal(subRes)
	if err != nil {
		return nil, fmt.Errorf("failed marshaling submission result: %w", err)
	}

	return &ToolCallResult{
		Content:           []TextContent{{Type: "text", Text: string(raw)}},
		StructuredContent: subRes,
	}, nil
}

func decodeFindingsJSONArg(raw json.RawMessage) (string, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return "", fmt.Errorf("%w: findings_json is required", lenses.ErrInvalidFindingsJSON)
	}
	if strings.HasPrefix(trimmed, `"`) {
		var str string
		if err := json.Unmarshal(raw, &str); err != nil {
			return "", fmt.Errorf("%w: %v", lenses.ErrInvalidFindingsJSON, err)
		}
		return str, nil
	}
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		return trimmed, nil
	}
	return "", fmt.Errorf("%w: findings_json must be a JSON string or object", lenses.ErrInvalidFindingsJSON)
}

func (s *Server) callConsolidatePrepare(ctx context.Context, args json.RawMessage, meta *ToolCallMeta) (*ToolCallResult, error) {
	if s.hostEval == nil {
		return nil, fmt.Errorf("host evaluator is not initialized")
	}
	var input struct {
		Project   string `json:"project"`
		SessionID string `json:"session_id"`
		MaxNodes  int    `json:"max_nodes"`
	}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &input); err != nil {
			return nil, fmt.Errorf("invalid arguments: %w", err)
		}
	}
	mgr, cleanup, err := s.getManagerForProject(input.Project)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	sessionID := strings.TrimSpace(input.SessionID)
	if sessionID == "" && meta != nil && meta.SessionID != "" {
		sessionID = strings.TrimSpace(meta.SessionID)
	}
	proj := strings.TrimSpace(input.Project)
	if proj == "" {
		proj = "default"
	}

	bundle, err := s.hostEval.PrepareConsolidation(ctx, mgr, proj, sessionID, input.MaxNodes)
	if err != nil {
		return nil, err
	}
	raw, _ := json.Marshal(bundle)
	return &ToolCallResult{
		Content:           []TextContent{{Type: "text", Text: string(raw)}},
		StructuredContent: bundle,
	}, nil
}

func (s *Server) callConsolidateSubmit(ctx context.Context, args json.RawMessage, meta *ToolCallMeta) (*ToolCallResult, error) {
	if s.hostEval == nil {
		return nil, fmt.Errorf("host evaluator is not initialized")
	}
	var input struct {
		EvalToken         string          `json:"eval_token"`
		ConsolidationJSON json.RawMessage `json:"consolidation_json"`
		Project           string          `json:"project"`
		SessionID         string          `json:"session_id"`
	}
	if err := json.Unmarshal(args, &input); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}
	rawJSON, err := decodeFindingsJSONArg(input.ConsolidationJSON)
	if err != nil {
		return nil, err
	}
	mgr, cleanup, err := s.getManagerForProject(input.Project)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	sessionID := strings.TrimSpace(input.SessionID)
	if sessionID == "" && meta != nil && meta.SessionID != "" {
		sessionID = strings.TrimSpace(meta.SessionID)
	}
	proj := strings.TrimSpace(input.Project)
	if proj == "" {
		proj = "default"
	}

	res, err := s.hostEval.SubmitConsolidation(ctx, mgr, proj, input.EvalToken, rawJSON, sessionID)
	if err != nil {
		return nil, err
	}
	raw, _ := json.Marshal(res)
	return &ToolCallResult{
		Content:           []TextContent{{Type: "text", Text: string(raw)}},
		StructuredContent: res,
	}, nil
}
