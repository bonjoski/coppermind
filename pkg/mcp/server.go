package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/bonjoski/coppermind/pkg/brain"
)

// Server implements a native Model Context Protocol (MCP) server over STDIO or arbitrary streams.
type Server struct {
	manager   *brain.Manager
	inMu      sync.Mutex
	outMu     sync.Mutex
	writer    io.Writer
	startTime time.Time
}

// NewServer creates a new MCP server wrapping the brain manager.
func NewServer(manager *brain.Manager, out io.Writer) *Server {
	if out == nil {
		out = os.Stdout
	}
	return &Server{
		manager:   manager,
		writer:    out,
		startTime: time.Now(),
	}
}

// ServeSTDIO starts reading JSON-RPC 2.0 messages from in and writing responses to the configured output.
func (s *Server) ServeSTDIO(ctx context.Context, in io.Reader) error {
	scanner := bufio.NewScanner(in)
	// Buffer size for handling large tool call payloads
	buf := make([]byte, 1024*1024)
	scanner.Buffer(buf, 10*1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}

		var msg JSONRPCMessage
		if err := json.Unmarshal(line, &msg); err != nil {
			errResp := NewErrorResponse(nil, ErrCodeParseError, "Invalid JSON-RPC 2.0 payload")
			_ = s.writeMessage(errResp)
			continue
		}

		resp := s.handleMessage(ctx, &msg)
		if resp != nil {
			if err := s.writeMessage(resp); err != nil {
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
					"category": { "type": "string", "description": "Category (e.g. architecture, convention, bug_fix, runbook)." },
					"session_id": { "type": "string", "description": "Optional session/worktree identifier." },
					"provenance": { "type": "string", "enum": ["TRUST_LOCAL_WORKSPACE", "TAINT_EXTERNAL_USER", "TAINT_UNTRUSTED_WEB"] }
				},
				"required": ["content"]
			}`),
		},
		{
			Name:        "coppermind_recall",
			Description: "Perform semantic similarity search over stored memories using cosine vector similarity.",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"query": { "type": "string", "description": "Natural language query to search memory for." },
					"category": { "type": "string", "description": "Optional category filter." },
					"session_id": { "type": "string", "description": "Optional session filter." },
					"limit": { "type": "integer", "description": "Max results to return (default 5)." },
					"min_score": { "type": "number", "description": "Minimum similarity score threshold (default 0.3)." }
				},
				"required": ["query"]
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
	case "coppermind_scratchpad":
		result, err = s.callScratchpad(ctx, params.Arguments)
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

func (s *Server) callRemember(ctx context.Context, args json.RawMessage) (*ToolCallResult, error) {
	var input struct {
		Content    string `json:"content"`
		Category   string `json:"category"`
		SessionID  string `json:"session_id"`
		Provenance string `json:"provenance"`
	}
	if err := json.Unmarshal(args, &input); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}

	prov := brain.ProvenanceLocalWorkspace
	if input.Provenance != "" {
		prov = brain.ProvenanceTier(input.Provenance)
	}

	node, err := s.manager.Remember(ctx, brain.RememberRequest{
		SessionID:  input.SessionID,
		Category:   input.Category,
		Content:    input.Content,
		Provenance: prov,
	})
	if err != nil {
		return nil, err
	}

	msg := fmt.Sprintf("Stored memory %s [%s] (%s): %s", node.ID, node.Category, node.Provenance, node.Content)
	return &ToolCallResult{
		Content: []TextContent{{Type: "text", Text: msg}},
	}, nil
}

func (s *Server) callRecall(ctx context.Context, args json.RawMessage) (*ToolCallResult, error) {
	var input struct {
		Query     string  `json:"query"`
		Category  string  `json:"category"`
		SessionID string  `json:"session_id"`
		Limit     int     `json:"limit"`
		MinScore  float32 `json:"min_score"`
	}
	if err := json.Unmarshal(args, &input); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}

	if input.Limit <= 0 {
		input.Limit = 5
	}
	if input.MinScore == 0 {
		input.MinScore = 0.3
	}

	results, err := s.manager.Recall(ctx, brain.RecallRequest{
		SessionID: input.SessionID,
		Category:  input.Category,
		Query:     input.Query,
		Limit:     input.Limit,
		MinScore:  input.MinScore,
	})
	if err != nil {
		return nil, err
	}

	if len(results) == 0 {
		return &ToolCallResult{
			Content: []TextContent{{Type: "text", Text: "No matching memories found above score threshold."}},
		}, nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Found %d relevant memories:\n\n", len(results)))
	for i, r := range results {
		sb.WriteString(fmt.Sprintf("%d. [Score: %.3f] [%s | %s]\n   %s\n\n",
			i+1, r.Score, r.Node.Category, r.Node.Provenance, r.Node.Content))
	}

	return &ToolCallResult{
		Content: []TextContent{{Type: "text", Text: strings.TrimSpace(sb.String())}},
	}, nil
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

func (s *Server) callStatus(ctx context.Context) (*ToolCallResult, error) {
	totalMemories, err := s.manager.Count(ctx, "")
	if err != nil {
		return nil, err
	}
	keys := s.manager.Scratchpad().Keys(ctx)

	status := fmt.Sprintf(
		"Coppermind Cognitive Brain Status:\n"+
			"• Total Stored Memories: %d\n"+
			"• Active Scratchpad Keys: %d\n"+
			"• Uptime: %s\n"+
			"• Protocol: MCP JSON-RPC 2.0 (STDIO / SSE)\n"+
			"• Storage Engine: Pure-Go SQLite WAL Mode + L2 Cosine Vector Index",
		totalMemories,
		len(keys),
		time.Since(s.startTime).Round(time.Second),
	)

	return &ToolCallResult{
		Content: []TextContent{{Type: "text", Text: status}},
	}, nil
}
