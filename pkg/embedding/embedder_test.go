package embedding

import (
	"context"
	"strings"
	"testing"
)

func TestLocalHashEmbedder_Similarity(t *testing.T) {
	ctx := context.Background()
	embedder := NewLocalHashEmbedder(128)

	text1 := "Go 1.27 SQLite database in WAL mode"
	text2 := "Go 1.27 SQLite database in WAL mode"
	text3 := "Pure Go SQLite database in Write Ahead Log mode"
	text4 := "Baking chocolate chip cookies with butter and sugar"

	v1, err := embedder.Embed(ctx, text1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	v2, err := embedder.Embed(ctx, text2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	v3, err := embedder.Embed(ctx, text3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	v4, err := embedder.Embed(ctx, text4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	simIdentical := CosineSimilarity(v1, v2)
	t.Logf("simIdentical: %f", simIdentical)
	if simIdentical < 0.999 {
		t.Errorf("expected ~1.0 for identical text, got %f", simIdentical)
	}

	simSimilar := CosineSimilarity(v1, v3)
	t.Logf("simSimilar: %f", simSimilar)
	if simSimilar < 0.45 {
		t.Errorf("expected > 0.45 for similar text, got %f", simSimilar)
	}

	simDifferent := CosineSimilarity(v1, v4)
	t.Logf("simDifferent: %f", simDifferent)
	if simDifferent > 0.25 {
		t.Errorf("expected < 0.25 for completely different topics, got %f", simDifferent)
	}

	if simSimilar <= simDifferent*1.5 {
		t.Errorf("similar score (%f) must be significantly greater than different score (%f)", simSimilar, simDifferent)
	}
}

func TestResilientEmbedder_Fallback(t *testing.T) {
	ctx := context.Background()
	dim := 768

	// Point Ollama embedder to a non-existent port to simulate offline service
	offlineOllama := NewOllamaEmbedder("http://127.0.0.1:59999", "nomic-embed-text", dim)
	fallback := NewLocalHashEmbedder(dim)
	resilient := NewResilientEmbedder(offlineOllama, fallback)

	if resilient.Dimension() != dim {
		t.Errorf("expected dimension %d, got %d", dim, resilient.Dimension())
	}

	vec, err := resilient.Embed(ctx, "Test memory with resilient fallback")
	if err != nil {
		t.Fatalf("expected fallback to succeed, got error: %v", err)
	}

	if len(vec) != dim {
		t.Errorf("expected vector dimension %d, got %d", dim, len(vec))
	}
}

func TestOpenAIEmbedder_Scrubbing(t *testing.T) {
	ctx := context.Background()

	// OpenAI embedder pointing to an offline port
	embedder := NewOpenAIEmbedder("http://127.0.0.1:59998", "sk-proj-secret1234567890abcdef123456", "text-embedding-3-small", 1536)
	_, err := embedder.Embed(ctx, "Hello world")
	if err == nil {
		t.Fatalf("expected error from offline server, got nil")
	}

	// Verify the error message doesn't leak raw secret key
	if strings.Contains(err.Error(), "sk-proj-secret1234567890abcdef123456") {
		t.Fatalf("critical security leak: OpenAI embedder echoed secret key in error: %v", err)
	}
}
