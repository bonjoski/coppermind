package embedding

import (
	"context"
	"encoding/binary"
	"errors"
	"math"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestAdversarial_CMVEC1MalformedAndOverflowHeaders(t *testing.T) {
	dir := t.TempDir()

	// 1. Bad magic
	badMagic := filepath.Join(dir, "bad_magic.cmvec")
	buf := make([]byte, CMVEC1HeaderSize+16)
	copy(buf[:8], "NOTVEC99")
	_ = os.WriteFile(badMagic, buf, 0600)
	if _, err := LoadStaticEmbedder(badMagic, ""); !errors.Is(err, ErrInvalidCMVEC1) {
		t.Fatalf("expected ErrInvalidCMVEC1 for bad magic, got %v", err)
	}

	// 2. Integer-overflow vocab_size = 0xFFFFFFFF (OOM DoS probe)
	overflowVocab := filepath.Join(dir, "overflow_vocab.cmvec")
	buf = make([]byte, CMVEC1HeaderSize+32)
	copy(buf[0:8], CMVEC1Magic)
	binary.LittleEndian.PutUint32(buf[8:12], CMVEC1Version)
	binary.LittleEndian.PutUint32(buf[12:16], 256)
	binary.LittleEndian.PutUint32(buf[16:20], 0xFFFFFFFF)
	buf[20] = CMVEC1QuantInt8Scale
	_ = os.WriteFile(overflowVocab, buf, 0600)
	if _, err := LoadStaticEmbedder(overflowVocab, ""); !errors.Is(err, ErrInvalidCMVEC1) {
		t.Fatalf("expected ErrInvalidCMVEC1 for vocab overflow, got %v", err)
	}

	// 3. Dimension > MaxCMVEC1Dimension
	overflowDim := filepath.Join(dir, "overflow_dim.cmvec")
	buf = make([]byte, CMVEC1HeaderSize+32)
	copy(buf[0:8], CMVEC1Magic)
	binary.LittleEndian.PutUint32(buf[8:12], CMVEC1Version)
	binary.LittleEndian.PutUint32(buf[12:16], MaxCMVEC1Dimension+1)
	binary.LittleEndian.PutUint32(buf[16:20], 1)
	buf[20] = CMVEC1QuantInt8Scale
	_ = os.WriteFile(overflowDim, buf, 0600)
	if _, err := LoadStaticEmbedder(overflowDim, ""); !errors.Is(err, ErrInvalidCMVEC1) {
		t.Fatalf("expected ErrInvalidCMVEC1 for dim overflow, got %v", err)
	}

	// 4. Truncated payload with valid small header
	truncated := filepath.Join(dir, "truncated.cmvec")
	buf = make([]byte, CMVEC1HeaderSize+10)
	copy(buf[0:8], CMVEC1Magic)
	binary.LittleEndian.PutUint32(buf[8:12], CMVEC1Version)
	binary.LittleEndian.PutUint32(buf[12:16], 128)
	binary.LittleEndian.PutUint32(buf[16:20], 10)
	buf[20] = CMVEC1QuantInt8Scale
	_ = os.WriteFile(truncated, buf, 0600)
	if _, err := LoadStaticEmbedder(truncated, ""); !errors.Is(err, ErrInvalidCMVEC1) {
		t.Fatalf("expected ErrInvalidCMVEC1 for truncated payload, got %v", err)
	}
}

func TestAdversarial_CMVEC1SymlinkAndChecksumRefusal(t *testing.T) {
	dir := t.TempDir()
	packPath := filepath.Join(dir, "valid.cmvec")
	sum, err := BuildSovereignDevPack(packPath)
	if err != nil {
		t.Fatalf("BuildSovereignDevPack failed: %v", err)
	}

	// 1. Symlink refusal fail-closed
	linkPath := filepath.Join(dir, "link.cmvec")
	if err := os.Symlink(packPath, linkPath); err != nil {
		t.Fatalf("symlink create failed: %v", err)
	}
	if _, err := LoadStaticEmbedder(linkPath, sum); !errors.Is(err, ErrCMVEC1SymlinkRejected) {
		t.Fatalf("expected ErrCMVEC1SymlinkRejected, got %v", err)
	}

	// 2. Pinned SHA-256 mismatch refusal
	if _, err := LoadStaticEmbedder(packPath, "0000000000000000000000000000000000000000000000000000000000000000"); !errors.Is(err, ErrCMVEC1ChecksumMismatch) {
		t.Fatalf("expected ErrCMVEC1ChecksumMismatch, got %v", err)
	}

	// 3. Bit-flip tampering inside payload fails embedded digest
	raw, err := os.ReadFile(packPath)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0xFF
	tampered := filepath.Join(dir, "tampered.cmvec")
	_ = os.WriteFile(tampered, raw, 0600)
	if _, err := LoadStaticEmbedder(tampered, ""); !errors.Is(err, ErrCMVEC1ChecksumMismatch) {
		t.Fatalf("expected ErrCMVEC1ChecksumMismatch for tampered payload, got %v", err)
	}
}

func TestStaticEmbedder_SemanticSynonymsAndN8Concurrency(t *testing.T) {
	dir := t.TempDir()
	packPath := filepath.Join(dir, "sovereign-dev-256.cmvec")
	sum, err := BuildSovereignDevPack(packPath)
	if err != nil {
		t.Fatalf("BuildSovereignDevPack failed: %v", err)
	}

	emb, err := LoadStaticEmbedder(packPath, sum)
	if err != nil {
		t.Fatalf("LoadStaticEmbedder failed: %v", err)
	}

	ctx := context.Background()
	vAuth, _ := emb.Embed(ctx, "login credential expiry")
	vToken, _ := emb.Embed(ctx, "authentication token ttl")
	vUnrelated, _ := emb.Embed(ctx, "sqlite vacuum migration")

	simRelated := CosineSimilarity(vAuth, vToken)
	simUnrelated := CosineSimilarity(vAuth, vUnrelated)
	if simRelated <= simUnrelated+0.25 {
		t.Fatalf("expected strong semantic synonym separation: related=%.3f unrelated=%.3f", simRelated, simUnrelated)
	}

	// Quantization round-trip fidelity check
	orig := make([]float32, 64)
	for i := range orig {
		orig[i] = float32(math.Sin(float64(i) * 0.3))
	}
	normalize(orig)
	rtPath := filepath.Join(dir, "rt.cmvec")
	rtSum, err := SaveCMVEC1(rtPath, 64, []string{"probe"}, [][]float32{orig})
	if err != nil {
		t.Fatalf("SaveCMVEC1 failed: %v", err)
	}
	rtEmb, err := LoadStaticEmbedder(rtPath, rtSum)
	if err != nil {
		t.Fatalf("LoadStaticEmbedder failed: %v", err)
	}
	got, _ := rtEmb.Embed(ctx, "probe")
	if cs := CosineSimilarity(orig, got); cs < 0.995 {
		t.Fatalf("quantization round-trip fidelity too low: %.4f", cs)
	}

	// N=8 parallel lock-free concurrent Embed calls
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				v, err := emb.Embed(ctx, "authentication spiffe token sandbox isolation")
				if err != nil || len(v) != 256 {
					t.Errorf("unexpected embed error: %v len=%d", err, len(v))
				}
			}
		}()
	}
	wg.Wait()
}
