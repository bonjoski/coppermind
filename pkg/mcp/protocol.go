package mcp

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Standard JSON-RPC 2.0 error codes
const (
	ErrCodeParseError     = -32700
	ErrCodeInvalidRequest = -32600
	ErrCodeMethodNotFound = -32601
	ErrCodeInvalidParams  = -32602
	ErrCodeInternalError  = -32603
)

// UB-MCP-v1 deterministic exit codes (RFC-2026-11-22-49).
const (
	ExitCodeOK               = 0
	ExitCodeRuntimeErr       = 1
	ExitCodePolicyDeny       = 10
	ExitCodeSupplyChainBlock = 20
	ExitCodeSandboxViolation = 30
	ExitCodeSecretGuardBlock = 40
	ExitCodeBiometricReq     = 82

	UBMCPv1SchemaVersion = "ub-cli-v2"
	CoppermindToolName   = "coppermind"
)

var (
	ubCodeRe    = regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,63}$`)
	ubReceiptRe = regexp.MustCompile(`^rcpt_[0-9A-Za-z]+$`)
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
	Meta      *ToolCallMeta   `json:"_meta,omitempty"`
}

// ToolCallMeta carries optional cross-tool MCP correlation headers propagated by Conjoiner/Fabrial.
type ToolCallMeta struct {
	FabrialSessionID string `json:"FABRIAL_SESSION_ID,omitempty"`
	ConjoinerSIRID   string `json:"CONJOINER_SIR_ID,omitempty"`
	SessionID        string `json:"session_id,omitempty"`
}

// TextContent represents a standard text output item in an MCP tool response.
type TextContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// ToolCallResult represents the standard result for tools/call.
type ToolCallResult struct {
	Content           []TextContent `json:"content"`
	StructuredContent any           `json:"structuredContent,omitempty"`
	IsError           bool          `json:"isError,omitempty"`
}

// CallToolResult is an alias for ToolCallResult matching the MCP specification type name.
type CallToolResult = ToolCallResult

// SelfHealSuggestion defines an allowlisted self-correction suggestion in UB-MCP-v1.
type SelfHealSuggestion struct {
	SuggestedTool         string         `json:"suggested_tool"`
	SuggestedArgs         map[string]any `json:"suggested_args"`
	RequiresHumanApproval bool           `json:"requires_human_approval"`
}

// FixForwardError conforms strictly to ub-mcp-v1-error.schema.json (additionalProperties: false).
type FixForwardError struct {
	SchemaVersion  string              `json:"schema_version"`
	Tool           string              `json:"tool"`
	Code           string              `json:"code"`
	ExitCode       int                 `json:"exit_code"`
	Retryable      bool                `json:"retryable"`
	Summary        string              `json:"summary"`
	RemediationCmd string              `json:"remediation_cmd"`
	Why            string              `json:"why"`
	DeepWhy        string              `json:"deep_why,omitempty"`
	SelfHeal       *SelfHealSuggestion `json:"self_heal,omitempty"`
	ReceiptID      string              `json:"receipt_id,omitempty"`
	References     []string            `json:"references,omitempty"`
}

// NewUBMCPv1ErrorResult constructs a UB-MCP-v1 compliant CallToolResult (isError: true)
// with ANSI-sanitized calm <=3-line human text and schema-conformant structuredContent.
func NewUBMCPv1ErrorResult(payload FixForwardError) *ToolCallResult {
	code := SanitizeSingleLine(strings.ToUpper(payload.Code))
	if !ubCodeRe.MatchString(code) {
		code = "COPPERMIND_POLICY_DENY"
	}

	exitCode := payload.ExitCode
	switch exitCode {
	case ExitCodeRuntimeErr, ExitCodePolicyDeny, ExitCodeSupplyChainBlock,
		ExitCodeSandboxViolation, ExitCodeSecretGuardBlock, ExitCodeBiometricReq:
	default:
		exitCode = ExitCodePolicyDeny
	}

	summary := truncateString(SanitizeSingleLine(payload.Summary), 240)
	if summary == "" {
		summary = "Operation paused by Coppermind validation policy."
	}

	remediation := truncateString(SanitizeSingleLine(payload.RemediationCmd), 256)
	if remediation == "" {
		remediation = "coppermind doctor"
	}

	why := truncateString(SanitizeSingleLine(payload.Why), 280)
	if why == "" {
		why = "Coppermind enforces fail-closed quarantine and schema validation before persisting or recalling context."
	}

	deepWhy := truncateString(strings.TrimSpace(SanitizeTerminalText(payload.DeepWhy)), 2048)

	receiptID := SanitizeSingleLine(payload.ReceiptID)
	if receiptID != "" && !ubReceiptRe.MatchString(receiptID) {
		receiptID = ""
	}

	var refs []string
	for _, r := range payload.References {
		cleanRef := SanitizeSingleLine(r)
		if cleanRef != "" {
			refs = append(refs, cleanRef)
		}
	}

	clean := FixForwardError{
		SchemaVersion:  UBMCPv1SchemaVersion,
		Tool:           CoppermindToolName,
		Code:           code,
		ExitCode:       exitCode,
		Retryable:      payload.Retryable,
		Summary:        summary,
		RemediationCmd: remediation,
		Why:            why,
		DeepWhy:        deepWhy,
		SelfHeal:       payload.SelfHeal,
		ReceiptID:      receiptID,
		References:     refs,
	}

	calmText := fmt.Sprintf("⚠ %s: %s\n  Fix:  %s\n  Why:  %s",
		clean.Tool, clean.Summary, clean.RemediationCmd, clean.Why)

	return &ToolCallResult{
		IsError:           true,
		Content:           []TextContent{{Type: "text", Text: calmText}},
		StructuredContent: clean,
	}
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	// Trim safely on rune boundaries
	out := make([]rune, 0, maxLen)
	byteCount := 0
	for _, r := range s {
		rLen := len(string(r))
		if byteCount+rLen > maxLen-3 {
			break
		}
		out = append(out, r)
		byteCount += rLen
	}
	return strings.TrimSpace(string(out)) + "..."
}

// SanitizeSingleLine strips ANSI/terminal escape sequences, control characters, bidi overrides,
// and Unicode tag smuggling, then collapses newlines and tabs into single spaces.
func SanitizeSingleLine(s string) string {
	clean := SanitizeTerminalText(s)
	clean = strings.ReplaceAll(clean, "\n", " ")
	clean = strings.ReplaceAll(clean, "\r", " ")
	clean = strings.ReplaceAll(clean, "\t", " ")
	return strings.TrimSpace(clean)
}

// SanitizeTerminalText strips ESC, CSI, OSC, DCS/SOS/PM/APC, 8-bit C1 controls, C0 controls
// (except \n and \t), DEL, Unicode bidi overrides/isolates, zero-width formatters, and Plane 14 tags.
func SanitizeTerminalText(s string) string {
	runes := []rune(s)
	var b strings.Builder
	b.Grow(len(s))

	for i := 0; i < len(runes); i++ {
		r := runes[i]

		// Handle ESC (0x1B) sequences
		if r == 0x1b {
			if i+1 >= len(runes) {
				break
			}
			next := runes[i+1]
			switch next {
			case '[': // CSI sequence
				i += 2
				for i < len(runes) {
					c := runes[i]
					if c >= 0x40 && c <= 0x7e {
						break
					}
					i++
				}
			case ']', 'P', 'X', '^', '_': // OSC / DCS / SOS / PM / APC terminated by BEL or ST
				i += 2
				for i < len(runes) {
					if runes[i] == 0x07 || runes[i] == 0x9c {
						break
					}
					if runes[i] == 0x1b && i+1 < len(runes) && runes[i+1] == '\\' {
						i++
						break
					}
					i++
				}
			default:
				i++
				for i < len(runes) && runes[i] >= 0x20 && runes[i] <= 0x2f {
					i++
				}
			}
			continue
		}

		// Handle 8-bit C1 CSI (0x9B)
		if r == 0x9b {
			i++
			for i < len(runes) {
				c := runes[i]
				if c >= 0x40 && c <= 0x7e {
					break
				}
				i++
			}
			continue
		}

		// Handle 8-bit C1 OSC/DCS/SOS/PM/APC
		if r == 0x9d || r == 0x90 || r == 0x98 || r == 0x9e || r == 0x9f {
			i++
			for i < len(runes) {
				if runes[i] == 0x07 || runes[i] == 0x9c {
					break
				}
				if runes[i] == 0x1b && i+1 < len(runes) && runes[i+1] == '\\' {
					i++
					break
				}
				i++
			}
			continue
		}

		if r == '\n' || r == '\t' {
			b.WriteRune(r)
			continue
		}
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			continue
		}
		// Strip Unicode bidi overrides/isolates, zero-width formatters, and Plane 14 tag characters
		if (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) ||
			(r >= 0x200b && r <= 0x200f) || r == 0xfeff || (r >= 0xe0000 && r <= 0xe007f) {
			continue
		}

		b.WriteRune(r)
	}

	return b.String()
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
