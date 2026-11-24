package embedding

import (
	"os"
	"strings"
)

// NewEmbedderFromEnv inspects environment variables and instantiates the appropriate embedder.
// Resolution order:
//  1. Explicit COPPERMIND_EMBEDDER=ollama|openai (wrapped in ResilientEmbedder)
//  2. Explicit COPPERMIND_EMBEDDER=static OR auto-detected verified CMVEC1 pack at DefaultStaticModelPath()
//  3. LocalHashEmbedder(128) zero-dependency offline fallback (with concept-cluster synonym expansion)
func NewEmbedderFromEnv() Embedder {
	provider := strings.ToLower(strings.TrimSpace(os.Getenv("COPPERMIND_EMBEDDER")))

	switch provider {
	case "ollama":
		endpoint := os.Getenv("COPPERMIND_OLLAMA_URL")
		if endpoint == "" {
			endpoint = "http://localhost:11434"
		}
		model := os.Getenv("COPPERMIND_OLLAMA_MODEL")
		if model == "" {
			model = "nomic-embed-text"
		}
		dim := 768
		primary := NewOllamaEmbedder(endpoint, model, dim)
		fallback := NewLocalHashEmbedder(dim)
		return NewResilientEmbedder(primary, fallback)

	case "openai":
		baseURL := os.Getenv("COPPERMIND_OPENAI_URL")
		apiKey := os.Getenv("COPPERMIND_OPENAI_KEY")
		model := os.Getenv("COPPERMIND_OPENAI_MODEL")
		if model == "" {
			model = "text-embedding-3-small"
		}
		dim := 1536
		primary := NewOpenAIEmbedder(baseURL, apiKey, model, dim)
		fallback := NewLocalHashEmbedder(dim)
		return NewResilientEmbedder(primary, fallback)

	case "static", "cmvec", "cmvec1":
		packPath := DefaultStaticModelPath()
		expectedSHA := strings.TrimSpace(os.Getenv("COPPERMIND_STATIC_MODEL_SHA256"))
		if emb, err := LoadStaticEmbedder(packPath, expectedSHA); err == nil {
			return emb
		}
		return NewLocalHashEmbedder(DefaultDimension)

	case "hash", "local-hash":
		return NewLocalHashEmbedder(DefaultDimension)

	default:
		// Auto-discover verified local CMVEC1 pack if installed via `coppermind models pull`
		packPath := DefaultStaticModelPath()
		expectedSHA := strings.TrimSpace(os.Getenv("COPPERMIND_STATIC_MODEL_SHA256"))
		if emb, err := LoadStaticEmbedder(packPath, expectedSHA); err == nil {
			return emb
		}
		return NewLocalHashEmbedder(DefaultDimension)
	}
}
