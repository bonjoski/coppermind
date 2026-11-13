package embedding

import (
	"context"
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
