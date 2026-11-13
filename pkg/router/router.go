package router

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/bonjoski/coppermind/pkg/brain"
)

var keyScrubber = regexp.MustCompile(`\bsk-[a-zA-Z0-9_\-]{20,}\b`)

// Message represents a chat completion message.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// CompletionRequest represents the input to the LiteLLM/Model router.
type CompletionRequest struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	Temperature float32   `json:"temperature,omitempty"`
	MaxTokens   int       `json:"max_tokens,omitempty"`
}

// CompletionResponse represents the output from a model provider.
type CompletionResponse struct {
	Content          string `json:"content"`
	Model            string `json:"model"`
	PromptTokens     int    `json:"prompt_tokens,omitempty"`
	CompletionTokens int    `json:"completion_tokens,omitempty"`
}

// ModelRouter abstracts routing between local, proxy, and cloud models.
type ModelRouter interface {
	Complete(ctx context.Context, req *CompletionRequest) (*CompletionResponse, error)
	Reflect(ctx context.Context, sessionID string, memories []*brain.MemoryNode) (string, error)
}

// LiteLLMRouter provides an HTTP client adapter to LiteLLM Proxy / Ollama / OpenAI-compatible APIs.
type LiteLLMRouter struct {
	endpoint string
	apiKey   string
	client   *http.Client
}

// NewLiteLLMRouter creates a new router targeting an endpoint.
func NewLiteLLMRouter(endpoint, apiKey string) *LiteLLMRouter {
	if endpoint == "" {
		endpoint = "http://localhost:4000/v1"
	}
	return &LiteLLMRouter{
		endpoint: strings.TrimRight(endpoint, "/"),
		apiKey:   apiKey,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Complete dispatches a completion request with outbound credential error scrubbing.
func (r *LiteLLMRouter) Complete(ctx context.Context, req *CompletionRequest) (*CompletionResponse, error) {
	if req.Model == "" {
		req.Model = "default"
	}

	payload := map[string]interface{}{
		"model":       req.Model,
		"messages":    req.Messages,
		"temperature": req.Temperature,
	}
	if req.MaxTokens > 0 {
		payload["max_tokens"] = req.MaxTokens
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/chat/completions", r.endpoint)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if r.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+r.apiKey)
	}

	resp, err := r.client.Do(httpReq)
	if err != nil {
		// Scrub potential keys in connection errors
		scrubbed := keyScrubber.ReplaceAllString(err.Error(), "[REDACTED_KEY]")
		return nil, fmt.Errorf("model request failed: %s", scrubbed)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		// Scrub any credentials echoed back in upstream error body
		scrubbed := keyScrubber.ReplaceAllString(string(respBytes), "[REDACTED_KEY]")
		return nil, fmt.Errorf("upstream model provider error (status %d): %s", resp.StatusCode, scrubbed)
	}

	var chatResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
		Model string `json:"model"`
	}

	if err := json.Unmarshal(respBytes, &chatResp); err != nil {
		return nil, fmt.Errorf("failed to parse provider response: %w", err)
	}

	if len(chatResp.Choices) == 0 {
		return nil, fmt.Errorf("no completion choices returned by model")
	}

	return &CompletionResponse{
		Content:          chatResp.Choices[0].Message.Content,
		Model:            chatResp.Model,
		PromptTokens:     chatResp.Usage.PromptTokens,
		CompletionTokens: chatResp.Usage.CompletionTokens,
	}, nil
}

// Reflect extracts synthesized architectural takeaways from session memories.
func (r *LiteLLMRouter) Reflect(ctx context.Context, sessionID string, memories []*brain.MemoryNode) (string, error) {
	if len(memories) == 0 {
		return "No session memories available to reflect upon.", nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Reviewing session %s with %d episodic records:\n\n", sessionID, len(memories)))
	for i, m := range memories {
		sb.WriteString(fmt.Sprintf("- [%s | %s] %s\n", m.Category, m.CreatedAt.Format("15:04:05"), m.Content))
		if i >= 50 { // Cap context size for reflection
			break
		}
	}

	prompt := fmt.Sprintf(
		"You are Coppermind, an autonomous cognitive AI brain. Distill the following session memories "+
			"into key architectural invariants, decisions, and patterns discovered during execution:\n\n%s",
		sb.String(),
	)

	req := &CompletionRequest{
		Model: "default",
		Messages: []Message{
			{Role: "system", Content: "You are Coppermind, an expert cognitive reflection engine."},
			{Role: "user", Content: prompt},
		},
		Temperature: 0.2,
		MaxTokens:   512,
	}

	resp, err := r.Complete(ctx, req)
	if err != nil {
		// Offline fallback: synthesize structured reflection deterministically
		return fallbackReflection(sessionID, memories), nil
	}

	return resp.Content, nil
}

// fallbackReflection generates a structured rule and invariant distillation when offline.
func fallbackReflection(sessionID string, memories []*brain.MemoryNode) string {
	var categories = make(map[string]int)
	var keyTakeaways []string

	for _, m := range memories {
		categories[m.Category]++
		if m.Category == "invariant" || m.Category == "architecture" || m.Category == "decision" {
			keyTakeaways = append(keyTakeaways, m.Content)
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("### Autonomous Reflection: Session %s\n", sessionID))
	sb.WriteString(fmt.Sprintf("• Analyzed %d episodic records across categories: ", len(memories)))
	var catParts []string
	for k, v := range categories {
		catParts = append(catParts, fmt.Sprintf("%s (%d)", k, v))
	}
	sb.WriteString(strings.Join(catParts, ", ") + "\n\n")

	sb.WriteString("#### Key Synthesized Invariants:\n")
	if len(keyTakeaways) == 0 {
		sb.WriteString("• All operations completed within standard operational baselines.\n")
	} else {
		limit := 5
		if len(keyTakeaways) < limit {
			limit = len(keyTakeaways)
		}
		for i := 0; i < limit; i++ {
			sb.WriteString(fmt.Sprintf("• %s\n", keyTakeaways[i]))
		}
	}

	return sb.String()
}
