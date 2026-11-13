package mcp

import (
	"encoding/json"
)

// Standard JSON-RPC 2.0 error codes
const (
	ErrCodeParseError     = -32700
	ErrCodeInvalidRequest = -32600
	ErrCodeMethodNotFound = -32601
	ErrCodeInvalidParams  = -32602
	ErrCodeInternalError  = -32603
)

// JSONRPCMessage is the standard envelope for MCP communication.
type JSONRPCMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *JSONRPCError   `json:"error,omitempty"`
}

// JSONRPCError defines the error body.
type JSONRPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// ToolDef defines a tool exposed via tools/list.
type ToolDef struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

// ToolCallParams defines the payload for tools/call.
type ToolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// TextContent represents a standard text output item in an MCP tool response.
type TextContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// ToolCallResult represents the standard result for tools/call.
type ToolCallResult struct {
	Content []TextContent `json:"content"`
	IsError bool          `json:"isError,omitempty"`
}

// NewErrorResponse creates a standard error response envelope.
func NewErrorResponse(id json.RawMessage, code int, msg string) *JSONRPCMessage {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	return &JSONRPCMessage{
		JSONRPC: "2.0",
		ID:      id,
		Error: &JSONRPCError{
			Code:    code,
			Message: msg,
		},
	}
}

// NewSuccessResponse creates a successful response envelope.
func NewSuccessResponse(id json.RawMessage, result interface{}) (*JSONRPCMessage, error) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	return &JSONRPCMessage{
		JSONRPC: "2.0",
		ID:      id,
		Result:  raw,
	}, nil
}
