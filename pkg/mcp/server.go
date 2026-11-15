package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/embedding"
	"github.com/bonjoski/coppermind/pkg/project"
	"github.com/bonjoski/coppermind/pkg/queue"
	"github.com/bonjoski/coppermind/pkg/scratchpad"
	"github.com/bonjoski/coppermind/pkg/storage/sqlite"
	"github.com/bonjoski/coppermind/pkg/worker"
)

// Server implements a native Model Context Protocol (MCP) server over STDIO or arbitrary streams.
type Server struct {
	manager    *brain.Manager
	projectMgr *project.Manager
	broker     queue.Broker
	worker     *worker.CognitiveWorker
	inMu       sync.Mutex
	outMu      sync.Mutex
	writer     io.Writer
	startTime  time.Time
}

// NewServer creates a new MCP server wrapping the brain manager.
func NewServer(manager *brain.Manager, out io.Writer) *Server {
	if out == nil {
		out = os.Stdout
	}
	return &Server{
		manager:    manager,
		projectMgr: project.NewManager(""),
		writer:     out,
		startTime:  time.Now(),
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
			"version": "0.1.0",
		},
		"capabilities": map[string]interface{}{
			"tools": map[string]bool{
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
			Description: "Perform semantic and hybrid search over stored memories in a project vault, optionally filtering by cognitive lens or auto-attaching observations.",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"query": { "type": "string", "description": "Natural language query to search memory for." },
					"project": { "type": "string", "description": "Optional isolated project vault name (e.g. github, personal, work)." },
					"category": { "type": "string", "description": "Optional category filter." },
					"session_id": { "type": "string", "description": "Optional session filter." },
					"limit": { "type": "integer", "description": "Max results to return (default 5)." },
					"min_score": { "type": "number", "description": "Minimum similarity score threshold (default 0.0)." },
					"lens": { "type": "string", "description": "Optional cognitive lens filter to retrieve observations from a specific persona (e.g. security-architect, systems-architect, drift-auditor, synthesizer)." },
					"include_observations": { "type": "boolean", "description": "Whether to auto-attach linked cognitive lens observations to recalled memories (default true)." },
					"include_superseded": { "type": "boolean", "description": "Whether to include superseded historical memories in results (default false)." },
					"tier": { "type": "string", "description": "Optional authority tier filter (e.g. TIER_1_ARCHITECTURE)." }
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
			Description: "Interact with fast working memory (ephemeral key-value state, locks, and subagent coordination).",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"action": { "type": "string", "enum": ["get", "set", "delete", "lock", "keys"] },
					"key": { "type": "string", "description": "Key name." },
					"value": { "type": "string", "description": "Value to set (for 'set' action)." },
					"ttl_seconds": { "type": "integer", "description": "TTL in seconds for set or lock (default 300)." }
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
		result, err = s.callRecall(ctx, params.Arguments)
	case "coppermind_project":
		result, err = s.callProject(ctx, params.Arguments)
	case "coppermind_scratchpad":
		result, err = s.callScratchpad(ctx, params.Arguments)
	case "coppermind_dispatch_task":
		result, err = s.callDispatchTask(ctx, params.Arguments)
	case "coppermind_status":
		result, err = s.callStatus(ctx)
	default:
		return NewErrorResponse(msg.ID, ErrCodeMethodNotFound, fmt.Sprintf("Tool %q not found", params.Name))
	}

	if err != nil {
		result = &ToolCallResult{
			IsError: true,
			Content: []TextContent{{Type: "text", Text: fmt.Sprintf("Error: %v", err)}},
		}
	}

	resp, _ := NewSuccessResponse(msg.ID, result)
	return resp
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
	}
	return &ToolCallResult{
		Content: []TextContent{{Type: "text", Text: msg}},
	}, nil
}

func (s *Server) callRecall(ctx context.Context, args json.RawMessage) (*ToolCallResult, error) {
	var input struct {
		Project             string  `json:"project"`
		Query               string  `json:"query"`
		Category            string  `json:"category"`
		SessionID           string  `json:"session_id"`
		Limit               int     `json:"limit"`
		MinScore            float32 `json:"min_score"`
		Lens                string  `json:"lens"`
		IncludeObservations *bool   `json:"include_observations"`
		IncludeSuperseded   bool    `json:"include_superseded"`
		Tier                string  `json:"tier"`
	}
	if err := json.Unmarshal(args, &input); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}

	mgr, cleanup, err := s.getManagerForProject(input.Project)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	if input.Limit <= 0 {
		input.Limit = 5
	}

	includeObs := true
	if input.IncludeObservations != nil {
		includeObs = *input.IncludeObservations
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
	})
	if err != nil {
		return nil, err
	}

	if len(results) == 0 {
		return &ToolCallResult{
			Content: []TextContent{{Type: "text", Text: "No matching memories found."}},
		}, nil
	}

	targetProj := input.Project
	if targetProj == "" {
		targetProj = "active"
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Found %d relevant memories in project vault %q:\n\n", len(results), targetProj))
	for i, r := range results {
		sb.WriteString(fmt.Sprintf("%d. [Score: %.3f] [%s | %s]\n   %s\n",
			i+1, r.Score, r.Node.Category, r.Node.Provenance, r.Node.Content))
		if len(r.Observations) > 0 {
			sb.WriteString(fmt.Sprintf("   ↳ Linked Observations (%d):\n", len(r.Observations)))
			for _, obs := range r.Observations {
				sb.WriteString(fmt.Sprintf("     • [%s] (%s): %s\n",
					strings.ToUpper(obs.Severity), obs.SourceLens, obs.Content))
			}
		}
		sb.WriteString("\n")
	}

	return &ToolCallResult{
		Content: []TextContent{{Type: "text", Text: strings.TrimSpace(sb.String())}},
	}, nil
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
		Action     string `json:"action"`
		Key        string `json:"key"`
		Value      string `json:"value"`
		TTLSeconds int    `json:"ttl_seconds"`
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
