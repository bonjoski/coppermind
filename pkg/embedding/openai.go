package embedding

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
)

var openAIKeyScrubber = regexp.MustCompile(`sk-[a-zA-Z0-9_\-]{20,}`)

// OpenAIEmbedder connects to OpenAI or LiteLLM /v1/embeddings endpoints.
type OpenAIEmbedder struct {
	client    *http.Client
	baseURL   string
	apiKey    string
	model     string
	dimension int
}

type openAIEmbedRequest struct {
	Input string `json:"input"`
	Model string `json:"model"`
}

type openAIEmbedResponse struct {
	Data []struct {
		Embedding []float64 `json:"embedding"`
		Index     int       `json:"index"`
	} `json:"data"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// NewOpenAIEmbedder creates a new OpenAI/LiteLLM embedder.
func NewOpenAIEmbedder(baseURL, apiKey, model string, dim int) *OpenAIEmbedder {
	if baseURL == "" {
		baseURL = "https://api.openai.com/v1"
	}
	baseURL = strings.TrimSuffix(baseURL, "/")
	if model == "" {
		model = "text-embedding-3-small"
	}
	if dim <= 0 {
		dim = 1536
	}

	return &OpenAIEmbedder{
		client: &http.Client{
			Timeout: 8 * time.Second,
		},
		baseURL:   baseURL,
		apiKey:    apiKey,
		model:     model,
		dimension: dim,
	}
}

// Dimension returns the expected embedding dimensionality.
func (e *OpenAIEmbedder) Dimension() int {
	return e.dimension
}

// Embed calls the /v1/embeddings endpoint.
func (e *OpenAIEmbedder) Embed(ctx context.Context, text string) ([]float32, error) {
	reqBody := openAIEmbedRequest{
		Input: text,
		Model: e.model,
	}
	payload, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to encode embedding request: %w", err)
	}

	url := fmt.Sprintf("%s/embeddings", e.baseURL)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to create http request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if e.apiKey != "" {
		httpReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", e.apiKey))
	}

	resp, err := e.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("embedding request failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Adversarial defense: scrub any API keys that might be echoed in error messages
	scrubbedBody := openAIKeyScrubber.ReplaceAllString(string(bodyBytes), "[REDACTED_KEY]")

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("embedding API error (status %d): %s", resp.StatusCode, scrubbedBody)
	}

	var res openAIEmbedResponse
	if err := json.Unmarshal([]byte(scrubbedBody), &res); err != nil {
		return nil, fmt.Errorf("failed to decode embedding response: %w", err)
	}

	if res.Error != nil && res.Error.Message != "" {
		return nil, fmt.Errorf("embedding API returned error: %s", res.Error.Message)
	}

	if len(res.Data) == 0 || len(res.Data[0].Embedding) == 0 {
		return nil, fmt.Errorf("empty embedding returned from API")
	}

	rawVec := res.Data[0].Embedding
	vec := make([]float32, len(rawVec))
	for i, v := range rawVec {
		vec[i] = float32(v)
	}

	normalize(vec)
	return vec, nil
}
