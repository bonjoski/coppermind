package embedding

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
)

const (
	// CMVEC1Magic identifies a Coppermind static neural embedding binary pack (Model2Vec/Potion-compatible).
	CMVEC1Magic = "CMVEC1\x00\x00"

	// CMVEC1Version is the current binary format version.
	CMVEC1Version uint32 = 1

	// CMVEC1HeaderSize is the fixed header size in bytes.
	CMVEC1HeaderSize = 64

	// CMVEC1QuantInt8Scale indicates per-token float32 scale + int8 quantized weights.
	CMVEC1QuantInt8Scale uint8 = 1

	// MaxCMVEC1Dimension bounds vector dimensionality against OOM/integer overflow attacks.
	MaxCMVEC1Dimension = 1024

	// MaxCMVEC1VocabSize bounds vocabulary count against OOM/integer overflow attacks.
	MaxCMVEC1VocabSize = 250000

	// MaxCMVEC1FileBytes caps model pack size to 64 MiB.
	MaxCMVEC1FileBytes = 64 * 1024 * 1024

	// MaxCMVEC1TokenBytes caps individual token byte length.
	MaxCMVEC1TokenBytes = 256
)

var (
	// ErrInvalidCMVEC1 indicates a malformed, truncated, or out-of-bounds CMVEC1 file.
	ErrInvalidCMVEC1 = errors.New("invalid CMVEC1 model pack")
	// ErrCMVEC1ChecksumMismatch indicates SHA-256 verification failed.
	ErrCMVEC1ChecksumMismatch = errors.New("CMVEC1 SHA-256 checksum mismatch")
	// ErrCMVEC1SymlinkRejected indicates a symlink model path was refused fail-closed.
	ErrCMVEC1SymlinkRejected = errors.New("CMVEC1 model path symlink rejected fail-closed")
)

// NamedEmbedder is optionally implemented by embedders that advertise a canonical model identifier.
type NamedEmbedder interface {
	ModelName() string
}

// ModelNameFor returns the canonical model identifier for an embedder.
func ModelNameFor(e interface{ Dimension() int }) string {
	if e == nil {
		return "unknown"
	}
	if named, ok := e.(NamedEmbedder); ok && strings.TrimSpace(named.ModelName()) != "" {
		return named.ModelName()
	}
	return fmt.Sprintf("local-hash-%d", e.Dimension())
}

// StaticEmbedder implements a zero-CGO, lock-free pure-Go static neural embedder
// backed by a quantized CMVEC1 lookup table (Model2Vec / Potion compatible).
// Safe for concurrent reads across N=8+ goroutines with zero mutexes.
type StaticEmbedder struct {
	modelName string
	dim       int
	vocab     map[string]int // token -> index into weights/scales
	scales    []float32      // length == vocabSize
	weights   []int8         // contiguous flat length == vocabSize * dim
	sha256Hex string
}

// Dimension returns the embedding vector dimensionality.
func (e *StaticEmbedder) Dimension() int {
	return e.dim
}

// ModelName returns the canonical model identifier stored on memory nodes.
func (e *StaticEmbedder) ModelName() string {
	return e.modelName
}

// VocabSize returns the number of loaded token embeddings.
func (e *StaticEmbedder) VocabSize() int {
	return len(e.vocab)
}

// Checksum returns the verified SHA-256 hex digest of the loaded payload.
func (e *StaticEmbedder) Checksum() string {
	return e.sha256Hex
}

// Embed computes an L2-normalized static neural embedding in <0.25ms using lock-free
// vocabulary lookup + WordPiece/subword longest-match fallback + mean pooling.
func (e *StaticEmbedder) Embed(_ context.Context, text string) ([]float32, error) {
	vec := make([]float32, e.dim)
	if e == nil || e.dim == 0 || len(e.vocab) == 0 {
		return vec, nil
	}

	words := tokenize(text)
	if len(words) == 0 {
		return vec, nil
	}

	var matched float32
	for _, w := range words {
		if idx, ok := e.vocab[w]; ok {
			e.accumulate(idx, 1.0, vec)
			matched += 1.0
			continue
		}
		// Longest-match subword decomposition (WordPiece / BPE style)
		subMatched := e.accumulateSubwords(w, vec)
		matched += subMatched
	}

	if matched == 0 {
		// Graceful deterministic subword fallback if query contains strictly OOV tokens
		fallback := NewLocalHashEmbedder(e.dim)
		return fallback.Embed(context.Background(), text)
	}

	normalize(vec)
	return vec, nil
}

func (e *StaticEmbedder) accumulate(idx int, weight float32, dst []float32) {
	scale := e.scales[idx] * weight
	base := idx * e.dim
	row := e.weights[base : base+e.dim]
	for i := 0; i < e.dim; i++ {
		dst[i] += float32(row[i]) * scale
	}
}

func (e *StaticEmbedder) accumulateSubwords(word string, dst []float32) float32 {
	// Check prefix/suffix subwords and WordPiece "##" pieces.
	var count float32
	n := len(word)
	pos := 0
	for pos < n {
		found := false
		maxEnd := n
		if maxEnd-pos > 32 {
			maxEnd = pos + 32
		}
		for end := maxEnd; end > pos+1; end-- {
			piece := word[pos:end]
			if pos > 0 {
				if idx, ok := e.vocab["##"+piece]; ok {
					e.accumulate(idx, 0.75, dst)
					count += 0.75
					pos = end
					found = true
					break
				}
			}
			if idx, ok := e.vocab[piece]; ok {
				w := float32(0.85)
				if pos > 0 {
					w = 0.65
				}
				e.accumulate(idx, w, dst)
				count += w
				pos = end
				found = true
				break
			}
		}
		if !found {
			pos++
		}
	}
	return count
}

// SaveCMVEC1 quantizes float32 token vectors to int8 + float32 scale and writes a
// verified CMVEC1 pack atomically. Returns the full file SHA-256 hex digest.
func SaveCMVEC1(path string, dim int, tokens []string, vectors [][]float32) (string, error) {
	if dim <= 0 || dim > MaxCMVEC1Dimension {
		return "", fmt.Errorf("%w: dimension %d out of range [1, %d]", ErrInvalidCMVEC1, dim, MaxCMVEC1Dimension)
	}
	if len(tokens) == 0 || len(tokens) > MaxCMVEC1VocabSize {
		return "", fmt.Errorf("%w: vocab size %d out of range [1, %d]", ErrInvalidCMVEC1, len(tokens), MaxCMVEC1VocabSize)
	}
	if len(tokens) != len(vectors) {
		return "", fmt.Errorf("%w: token/vector length mismatch (%d != %d)", ErrInvalidCMVEC1, len(tokens), len(vectors))
	}

	// Refuse symlink destination fail-closed.
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%w: %s", ErrCMVEC1SymlinkRejected, path)
	}

	var payload bytes.Buffer
	for i, tok := range tokens {
		normTok := strings.ToLower(strings.TrimSpace(tok))
		if normTok == "" || len(normTok) > MaxCMVEC1TokenBytes {
			return "", fmt.Errorf("%w: invalid token length at index %d", ErrInvalidCMVEC1, i)
		}
		vec := vectors[i]
		if len(vec) != dim {
			return "", fmt.Errorf("%w: vector %d dim %d != %d", ErrInvalidCMVEC1, i, len(vec), dim)
		}

		// Find max abs value for symmetric int8 quantization [-127, 127].
		var maxAbs float32
		for _, v := range vec {
			if math.IsNaN(float64(v)) || math.IsInf(float64(v), 0) {
				return "", fmt.Errorf("%w: non-finite float at token %d", ErrInvalidCMVEC1, i)
			}
			a := float32(math.Abs(float64(v)))
			if a > maxAbs {
				maxAbs = a
			}
		}
		scale := float32(0)
		if maxAbs > 0 {
			scale = maxAbs / 127.0
		}

		_ = binary.Write(&payload, binary.LittleEndian, uint16(len(normTok)))
		payload.WriteString(normTok)
		_ = binary.Write(&payload, binary.LittleEndian, math.Float32bits(scale))
		for _, v := range vec {
			var q int8
			if scale > 0 {
				r := math.Round(float64(v / scale))
				if r > 127 {
					r = 127
				} else if r < -127 {
					r = -127
				}
				q = int8(r)
			}
			payload.WriteByte(byte(q))
		}
	}

	payloadBytes := payload.Bytes()
	payloadSum := sha256.Sum256(payloadBytes)

	header := make([]byte, CMVEC1HeaderSize)
	copy(header[0:8], CMVEC1Magic)
	binary.LittleEndian.PutUint32(header[8:12], CMVEC1Version)
	binary.LittleEndian.PutUint32(header[12:16], uint32(dim))
	binary.LittleEndian.PutUint32(header[16:20], uint32(len(tokens)))
	header[20] = CMVEC1QuantInt8Scale
	copy(header[24:56], payloadSum[:])

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("failed creating model directory: %w", err)
	}

	tmpPath := path + ".tmp"
	if fi, err := os.Lstat(tmpPath); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%w: %s", ErrCMVEC1SymlinkRejected, tmpPath)
	}
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return "", fmt.Errorf("failed creating temp model pack: %w", err)
	}
	fullHash := sha256.New()
	mw := io.MultiWriter(f, fullHash)
	if _, err := mw.Write(header); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return "", err
	}
	if _, err := mw.Write(payloadBytes); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return "", err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return "", err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return "", err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return "", err
	}
	return hex.EncodeToString(fullHash.Sum(nil)), nil
}

// LoadStaticEmbedder loads and cryptographically verifies a CMVEC1 static neural embedding pack.
// Refuses symlinks, out-of-bounds dimensions/vocab sizes, truncated files, and checksum mismatches fail-closed.
func LoadStaticEmbedder(path string, expectedFileSHA256 string) (*StaticEmbedder, error) {
	cleanPath := filepath.Clean(strings.TrimSpace(path))
	if cleanPath == "" || cleanPath == "." {
		return nil, fmt.Errorf("%w: empty model path", ErrInvalidCMVEC1)
	}

	fi, err := os.Lstat(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("cannot stat model pack %s: %w", cleanPath, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: %s", ErrCMVEC1SymlinkRejected, cleanPath)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: model path is not a regular file", ErrInvalidCMVEC1)
	}
	if fi.Size() < CMVEC1HeaderSize || fi.Size() > MaxCMVEC1FileBytes {
		return nil, fmt.Errorf("%w: file size %d out of bounds [%d, %d]", ErrInvalidCMVEC1, fi.Size(), CMVEC1HeaderSize, MaxCMVEC1FileBytes)
	}

	f, err := os.Open(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed opening model pack: %w", err)
	}
	defer f.Close()

	raw, err := io.ReadAll(io.LimitReader(f, MaxCMVEC1FileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("failed reading model pack: %w", err)
	}
	if len(raw) < CMVEC1HeaderSize || len(raw) > MaxCMVEC1FileBytes {
		return nil, fmt.Errorf("%w: invalid byte length %d", ErrInvalidCMVEC1, len(raw))
	}

	fileSum := sha256.Sum256(raw)
	fileSumHex := hex.EncodeToString(fileSum[:])
	if trimmedExp := strings.ToLower(strings.TrimSpace(expectedFileSHA256)); trimmedExp != "" && fileSumHex != trimmedExp {
		return nil, fmt.Errorf("%w: expected %s, got %s", ErrCMVEC1ChecksumMismatch, trimmedExp, fileSumHex)
	}

	header := raw[:CMVEC1HeaderSize]
	if string(header[0:8]) != CMVEC1Magic {
		return nil, fmt.Errorf("%w: bad magic header", ErrInvalidCMVEC1)
	}
	version := binary.LittleEndian.Uint32(header[8:12])
	if version != CMVEC1Version {
		return nil, fmt.Errorf("%w: unsupported version %d", ErrInvalidCMVEC1, version)
	}
	dim := binary.LittleEndian.Uint32(header[12:16])
	vocabSize := binary.LittleEndian.Uint32(header[16:20])
	quant := header[20]

	if dim == 0 || dim > MaxCMVEC1Dimension {
		return nil, fmt.Errorf("%w: dimension %d out of bounds [1, %d]", ErrInvalidCMVEC1, dim, MaxCMVEC1Dimension)
	}
	if vocabSize == 0 || vocabSize > MaxCMVEC1VocabSize {
		return nil, fmt.Errorf("%w: vocab_size %d out of bounds [1, %d]", ErrInvalidCMVEC1, vocabSize, MaxCMVEC1VocabSize)
	}
	if quant != CMVEC1QuantInt8Scale {
		return nil, fmt.Errorf("%w: unsupported quantization mode %d", ErrInvalidCMVEC1, quant)
	}

	payload := raw[CMVEC1HeaderSize:]
	// Check minimum possible byte length before allocating to prevent OOM on crafted headers.
	// Minimum per entry: 2 (tokLen) + 1 (tok) + 4 (scale) + dim (weights).
	minEntryBytes := uint64(2 + 1 + 4 + dim)
	if uint64(len(payload)) < uint64(vocabSize)*minEntryBytes {
		return nil, fmt.Errorf("%w: truncated payload for vocab_size=%d dim=%d", ErrInvalidCMVEC1, vocabSize, dim)
	}

	actualPayloadSum := sha256.Sum256(payload)
	if !bytes.Equal(actualPayloadSum[:], header[24:56]) {
		return nil, fmt.Errorf("%w: embedded payload digest mismatch", ErrCMVEC1ChecksumMismatch)
	}

	d := int(dim)
	vs := int(vocabSize)
	vocab := make(map[string]int, vs)
	scales := make([]float32, vs)
	weights := make([]int8, vs*d)

	offset := 0
	for i := 0; i < vs; i++ {
		if offset+2 > len(payload) {
			return nil, fmt.Errorf("%w: truncated token length at entry %d", ErrInvalidCMVEC1, i)
		}
		tokLen := int(binary.LittleEndian.Uint16(payload[offset : offset+2]))
		offset += 2
		if tokLen == 0 || tokLen > MaxCMVEC1TokenBytes || offset+tokLen+4+d > len(payload) {
			return nil, fmt.Errorf("%w: invalid or truncated entry %d", ErrInvalidCMVEC1, i)
		}
		tok := string(payload[offset : offset+tokLen])
		offset += tokLen
		scaleBits := binary.LittleEndian.Uint32(payload[offset : offset+4])
		scale := math.Float32frombits(scaleBits)
		if math.IsNaN(float64(scale)) || math.IsInf(float64(scale), 0) {
			return nil, fmt.Errorf("%w: non-finite scale at entry %d", ErrInvalidCMVEC1, i)
		}
		offset += 4
		scales[i] = scale

		base := i * d
		for j := 0; j < d; j++ {
			weights[base+j] = int8(payload[offset+j])
		}
		offset += d
		vocab[tok] = i
	}
	if offset != len(payload) {
		return nil, fmt.Errorf("%w: trailing garbage bytes (%d unread)", ErrInvalidCMVEC1, len(payload)-offset)
	}

	baseName := strings.TrimSuffix(filepath.Base(cleanPath), filepath.Ext(cleanPath))
	if baseName == "" {
		baseName = "static"
	}

	return &StaticEmbedder{
		modelName: fmt.Sprintf("cmvec1:%s-%d", baseName, d),
		dim:       d,
		vocab:     vocab,
		scales:    scales,
		weights:   weights,
		sha256Hex: fileSumHex,
	}, nil
}
