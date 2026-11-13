package embedding

import (
	"context"
	"fmt"
	"os"
)

// Embedder defines the common interface for generating vector embeddings.
type Embedder interface {
	Embed(ctx context.Context, text string) ([]float32, error)
	Dimension() int
}

// ResilientEmbedder wraps a primary remote embedder with a deterministic local fallback embedder.
// If the primary embedder experiences network errors, timeouts, or 500s, it automatically falls back.
type ResilientEmbedder struct {
	primary  Embedder
	fallback Embedder
}

// NewResilientEmbedder creates a resilient embedder pair.
func NewResilientEmbedder(primary Embedder, fallback Embedder) *ResilientEmbedder {
	return &ResilientEmbedder{
		primary:  primary,
		fallback: fallback,
	}
}

// Dimension returns the dimensionality of the primary embedder.
func (r *ResilientEmbedder) Dimension() int {
	return r.primary.Dimension()
}

// Embed attempts primary embedding and falls back to deterministic local hashing if it fails.
func (r *ResilientEmbedder) Embed(ctx context.Context, text string) ([]float32, error) {
	if r.primary != nil {
		vec, err := r.primary.Embed(ctx, text)
		if err == nil && len(vec) == r.primary.Dimension() {
			return vec, nil
		}
		if os.Getenv("COPPERMIND_DEBUG") != "" {
			fmt.Fprintf(os.Stderr, "Coppermind warning: primary embedder failed (%v), falling back to local hash embedder\n", err)
		}
	}

	if r.fallback != nil {
		return r.fallback.Embed(ctx, text)
	}

	return nil, fmt.Errorf("no operational embedder available")
}
