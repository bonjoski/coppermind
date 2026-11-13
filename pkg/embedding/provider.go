package embedding

import (
	"os"
	"strings"
)

// NewEmbedderFromEnv inspects environment variables and instantiates the appropriate embedder.
// Defaults to LocalHashEmbedder for zero-dependency, instantaneous offline operation.
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

	default:
		return NewLocalHashEmbedder(DefaultDimension)
	}
}
