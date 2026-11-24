package sqlite

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/embedding"
)

func TestVectorCache_ConcurrentN8ReadWriteAndMixedDimensionFallback(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "vec_cache.db")
	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStore failed: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	hashEmb := embedding.NewLocalHashEmbedder(128)

	// Seed 40 nodes with 128-dim LocalHashEmbedder
	for i := 0; i < 40; i++ {
		content := fmt.Sprintf("Coppermind architectural invariant #%d using SQLite WAL single-writer ring", i)
		vec, _ := hashEmb.Embed(ctx, content)
		if err := store.Store(ctx, &brain.MemoryNode{
			ID:             fmt.Sprintf("mem_seed_%02d", i),
			SessionID:      "coppermind",
			Category:       "architecture",
			Content:        content,
			Vector:         vec,
			Provenance:     brain.ProvenanceLocalWorkspace,
			EmbeddingModel: hashEmb.ModelName(),
			EmbeddingDim:   128,
		}); err != nil {
			t.Fatalf("store failed: %v", err)
		}
	}

	// Build a 256-dim CMVEC1 pack (mixed dimension relative to existing 128-dim rows!)
	packPath := filepath.Join(dir, "dev256.cmvec")
	sum, err := embedding.BuildSovereignDevPack(packPath)
	if err != nil {
		t.Fatalf("BuildSovereignDevPack failed: %v", err)
	}
	staticEmb, err := embedding.LoadStaticEmbedder(packPath, sum)
	if err != nil {
		t.Fatalf("LoadStaticEmbedder failed: %v", err)
	}

	// Query with 256-dim vector BEFORE reindex: RecallHybrid MUST still rescue 128-dim rows via FTS5 BM25!
	q256, _ := staticEmb.Embed(ctx, "SQLite WAL single-writer ring")
	mixedRes, err := store.RecallHybrid(ctx, "SQLite WAL single-writer ring", q256, brain.MemoryFilter{Limit: 5})
	if err != nil {
		t.Fatalf("RecallHybrid failed on mixed dims: %v", err)
	}
	if len(mixedRes) == 0 {
		t.Fatalf("expected BM25 graceful rescue for mixed-dimension vault, got 0 results")
	}

	// Reindex vectors in micro-batches
	stats, err := store.ReindexVectors(ctx, staticEmb, staticEmb.ModelName(), 16, false)
	if err != nil {
		t.Fatalf("ReindexVectors failed: %v", err)
	}
	if stats.Reindexed != 40 || stats.Dimension != 256 {
		t.Fatalf("unexpected reindex stats: %+v", stats)
	}

	// Verify vector coverage is 100%
	cov, err := store.GetVectorCoverage(ctx, staticEmb.ModelName())
	if err != nil || cov.MatchingNodes != 40 {
		t.Fatalf("expected 40/40 matching nodes, got %+v err=%v", cov, err)
	}

	// N=8 parallel readers + writers exercising lock-free atomic vector slab
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 15; i++ {
				if i%3 == 0 {
					c := fmt.Sprintf("Parallel worker %d architecture decision %d", worker, i)
					v, _ := staticEmb.Embed(ctx, c)
					_ = store.Store(ctx, &brain.MemoryNode{
						ID:             fmt.Sprintf("mem_w%d_%d", worker, i),
						SessionID:      "coppermind",
						Category:       "decision",
						Content:        c,
						Vector:         v,
						Provenance:     brain.ProvenanceLocalWorkspace,
						EmbeddingModel: staticEmb.ModelName(),
						EmbeddingDim:   256,
					})
				} else {
					res, rErr := store.RecallHybrid(ctx, "SQLite WAL architecture", q256, brain.MemoryFilter{Limit: 5})
					if rErr != nil || len(res) == 0 {
						t.Errorf("concurrent recall failed: err=%v len=%d", rErr, len(res))
					}
				}
			}
		}(g)
	}
	wg.Wait()

	// Verify IncrementAccessBatch only increments TRUST_LOCAL_WORKSPACE nodes
	if err := store.IncrementAccessBatch(ctx, []string{"mem_seed_00"}, time.Now()); err != nil {
		t.Fatalf("IncrementAccessBatch failed: %v", err)
	}
	updated, err := store.GetByID(ctx, "mem_seed_00")
	if err != nil || updated.AccessCount != 1 {
		t.Fatalf("expected access_count=1, got %+v err=%v", updated, err)
	}
}
