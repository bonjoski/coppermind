package router

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/coppermind/pkg/brain"
)

func TestLiteLLMRouter_CompleteAndScrubber(t *testing.T) {
	ctx := context.Background()

	// 1. Mock server that returns a 401 error echoing a leaked key
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error": "Invalid API key: sk-proj-1234567890abcdef1234567890abcdef provided"}`))
	}))
	defer mockServer.Close()

	router := NewLiteLLMRouter(mockServer.URL, "sk-proj-testkey12345678901234567890")

	_, err := router.Complete(ctx, &CompletionRequest{
		Model: "gpt-4o",
		Messages: []Message{
			{Role: "user", Content: "Hello"},
		},
	})
	if err == nil {
		t.Fatalf("expected error from 401 response, got nil")
	}

	if strings.Contains(err.Error(), "sk-proj-1234567890abcdef1234567890abcdef") {
		t.Errorf("critical failure: raw API key was echoed in error: %v", err)
	}
	if !strings.Contains(err.Error(), "[REDACTED_KEY]") {
		t.Errorf("expected [REDACTED_KEY] in error message, got: %v", err)
	}
}

func TestLiteLLMRouter_FallbackReflection(t *testing.T) {
	ctx := context.Background()
	// Router pointing to a non-existent port triggers offline fallback
	router := NewLiteLLMRouter("http://127.0.0.1:54321/v1", "")

	memories := []*brain.MemoryNode{
		{
			ID:        "m1",
			SessionID: "sess-123",
			Category:  "architecture",
			Content:   "Always use Pure-Go SQLite in WAL mode",
			CreatedAt: time.Now(),
		},
		{
			ID:        "m2",
			SessionID: "sess-123",
			Category:  "security",
			Content:   "Strict fail-closed secret quarantine active",
			CreatedAt: time.Now(),
		},
	}

	reflection, err := router.Reflect(ctx, "sess-123", memories)
	if err != nil {
		t.Fatalf("unexpected reflection error: %v", err)
	}

	if !strings.Contains(reflection, "sess-123") {
		t.Errorf("expected session ID in reflection, got: %s", reflection)
	}
	if !strings.Contains(reflection, "Always use Pure-Go SQLite in WAL mode") {
		t.Errorf("expected architectural takeaway in reflection, got: %s", reflection)
	}
}
