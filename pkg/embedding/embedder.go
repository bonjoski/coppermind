package embedding

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"strings"
	"unicode"
)

const (
	// DefaultDimension is the vector dimension for the local deterministic embedder.
	DefaultDimension = 128
)

// LocalHashEmbedder implements a deterministic L2-normalized subword/word n-gram semantic embedder.
// It maps text tokens, bigrams, and character subwords into a fixed-dimension vector space using SHA projections.
type LocalHashEmbedder struct {
	dimension int
}

// NewLocalHashEmbedder creates an embedder producing vectors of the given dimension.
func NewLocalHashEmbedder(dim int) *LocalHashEmbedder {
	if dim <= 0 {
		dim = DefaultDimension
	}
	return &LocalHashEmbedder{dimension: dim}
}

// Dimension returns the vector dimensionality.
func (e *LocalHashEmbedder) Dimension() int {
	return e.dimension
}

// Embed generates an L2-normalized vector for input text.
func (e *LocalHashEmbedder) Embed(_ context.Context, text string) ([]float32, error) {
	vec := make([]float32, e.dimension)

	// Clean and tokenize words
	words := tokenize(text)
	if len(words) == 0 {
		return vec, nil
	}

	// Word unigrams, bigrams, and character subword n-grams (FastText style)
	for i, w := range words {
		e.projectFeature("w:"+w, 2.0, vec)

		// Character n-grams (3 to 5 chars) for subword similarity
		subword := "<" + w + ">"
		for n := 3; n <= 5 && n <= len(subword); n++ {
			for j := 0; j <= len(subword)-n; j++ {
				ngram := subword[j : j+n]
				e.projectFeature("c:"+ngram, 0.75, vec)
			}
		}

		// Word bigrams
		if i+1 < len(words) {
			bigram := w + "_" + words[i+1]
			e.projectFeature("b:"+bigram, 1.5, vec)
		}
	}

	// L2 normalization
	normalize(vec)
	return vec, nil
}

func (e *LocalHashEmbedder) projectFeature(feature string, weight float32, vec []float32) {
	h := sha256.Sum256([]byte(feature))
	idx1 := int(binary.BigEndian.Uint32(h[0:4])) % e.dimension
	idx2 := int(binary.BigEndian.Uint32(h[4:8])) % e.dimension
	idx3 := int(binary.BigEndian.Uint32(h[8:12])) % e.dimension

	sign1 := float32(1.0)
	if h[12]%2 == 0 {
		sign1 = -1.0
	}
	sign2 := float32(1.0)
	if h[13]%2 == 0 {
		sign2 = -1.0
	}
	sign3 := float32(1.0)
	if h[14]%2 == 0 {
		sign3 = -1.0
	}

	vec[idx1] += weight * sign1
	vec[idx2] += (weight * 0.5) * sign2
	vec[idx3] += (weight * 0.25) * sign3
}

func tokenize(text string) []string {
	lower := strings.ToLower(text)
	var tokens []string
	var current strings.Builder

	for _, r := range lower {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-' {
			current.WriteRune(r)
		} else {
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
		}
	}
	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}
	return tokens
}

func normalize(vec []float32) {
	var sumSq float64
	for _, v := range vec {
		sumSq += float64(v) * float64(v)
	}
	if sumSq == 0 {
		return
	}
	norm := float32(math.Sqrt(sumSq))
	for i := range vec {
		vec[i] /= norm
	}
}

// CosineSimilarity calculates the cosine similarity between two normalized float32 vectors.
func CosineSimilarity(a, b []float32) float32 {
	if len(a) != len(b) || len(a) == 0 {
		return 0.0
	}
	var dot float32
	for i := 0; i < len(a); i++ {
		dot += a[i] * b[i]
	}
	if dot > 1.0 {
		return 1.0
	}
	if dot < -1.0 {
		return -1.0
	}
	return dot
}
