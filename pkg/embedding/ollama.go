package embedding

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// OllamaEmbedder connects to a local or remote Ollama instance for dense vector embeddings.
type OllamaEmbedder struct {
	client    *http.Client
	endpoint  string
	model     string
	dimension int
}

type ollamaRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
}

type ollamaResponse struct {
	Embedding []float64 `json:"embedding"`
	Error     string    `json:"error,omitempty"`
}

// NewOllamaEmbedder creates a new Ollama embedder.
func NewOllamaEmbedder(endpoint, model string, dim int) *OllamaEmbedder {
	if endpoint == "" {
		endpoint = "http://localhost:11434"
	}
	if model == "" {
		model = "nomic-embed-text"
	}
	if dim <= 0 {
		dim = 768
	}

	return &OllamaEmbedder{
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
		endpoint:  endpoint,
		model:     model,
		dimension: dim,
	}
}

// Dimension returns the expected embedding dimensionality.
func (o *OllamaEmbedder) Dimension() int {
	return o.dimension
}

// Embed calls Ollama /api/embeddings.
func (o *OllamaEmbedder) Embed(ctx context.Context, text string) ([]float32, error) {
	reqBody := ollamaRequest{
		Model:  o.model,
		Prompt: text,
	}
	payload, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to encode ollama request: %w", err)
	}

	url := fmt.Sprintf("%s/api/embeddings", o.endpoint)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to create http request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := o.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("ollama request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ollama returned non-200 status: %d", resp.StatusCode)
	}

	var res ollamaResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, fmt.Errorf("failed to decode ollama response: %w", err)
	}
	if res.Error != "" {
		return nil, fmt.Errorf("ollama error: %s", res.Error)
	}

	vec := make([]float32, len(res.Embedding))
	for i, v := range res.Embedding {
		vec[i] = float32(v)
	}

	normalize(vec)
	return vec, nil
}
