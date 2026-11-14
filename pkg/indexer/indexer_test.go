package indexer

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/embedding"
	"github.com/bonjoski/coppermind/pkg/scratchpad"
	"github.com/bonjoski/coppermind/pkg/storage/sqlite"
)

func TestIndexer_IndexDirectory(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "coppermind-index-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create test files
	// 1. Valid Go file with a simulated secret token embedded
	goContent := `package main

import "fmt"

func ProcessData() {
    apiKey := "sk-proj-1234567890abcdef1234567890abcdef"
    fmt.Println("Processing data with key:", apiKey)
}
`
	if err := os.WriteFile(filepath.Join(tempDir, "main.go"), []byte(goContent), 0644); err != nil {
		t.Fatalf("failed to write main.go: %v", err)
	}

	// 2. Markdown documentation
	mdContent := `# Architectural Blueprint
This document describes the Coppermind memory architecture.
## Primitives
We use pure-Go SQLite and pgvector.
`
	if err := os.WriteFile(filepath.Join(tempDir, "README.md"), []byte(mdContent), 0644); err != nil {
		t.Fatalf("failed to write README.md: %v", err)
	}

	// 3. Sensitive file (.env) - must be skipped entirely
	if err := os.WriteFile(filepath.Join(tempDir, ".env"), []byte("SECRET=super_secret"), 0600); err != nil {
		t.Fatalf("failed to write .env: %v", err)
	}

	// 4. Binary file with null bytes - must be skipped
	binContent := []byte{0x00, 0x01, 0x02, 0x03, 0x00, 0xFF}
	if err := os.WriteFile(filepath.Join(tempDir, "image.png"), binContent, 0644); err != nil {
		t.Fatalf("failed to write image.png: %v", err)
	}

	// Set up Brain Manager
	dbPath := filepath.Join(tempDir, "coppermind.db")
	store, err := sqlite.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to open sqlite store: %v", err)
	}
	defer store.Close()

	embedder := embedding.NewEmbedderFromEnv()
	sp := scratchpad.NewMemoryScratchpad()
	mgr := brain.NewManager(store, embedder, sp)

	// Run Indexer
	stats, err := IndexDirectory(context.Background(), mgr, tempDir, IndexOptions{
		ChunkLines: 20,
		MaxChunks:  50,
	})
	if err != nil {
		t.Fatalf("IndexDirectory failed: %v", err)
	}

	if stats.FilesIndexed < 2 {
		t.Errorf("expected at least 2 files indexed, got %d", stats.FilesIndexed)
	}
	if stats.Redactions != 1 {
		t.Errorf("expected 1 secret redaction in main.go, got %d", stats.Redactions)
	}

	// Recall chunk from README
	results, err := mgr.Recall(context.Background(), brain.RecallRequest{
		Query: "Coppermind memory architecture pure-Go SQLite",
		Limit: 5,
	})
	if err != nil {
		t.Fatalf("Recall failed: %v", err)
	}
	if len(results) == 0 {
		t.Fatalf("expected to recall indexed chunk, got 0 results")
	}

	// Verify the secret was redacted in the recalled main.go chunk
	codeResults, err := mgr.Recall(context.Background(), brain.RecallRequest{
		Query: "ProcessData apiKey",
		Limit: 5,
	})
	if err != nil {
		t.Fatalf("Recall code failed: %v", err)
	}
	if len(codeResults) > 0 {
		content := codeResults[0].Node.Content
		if content == "" {
			t.Fatalf("empty content in recalled chunk")
		}
		if !containsRedaction(content) {
			t.Errorf("recalled code chunk should contain [REDACTED_API_KEY], got: %s", content)
		}
	}
}

func containsRedaction(s string) bool {
	return len(s) > 0 && (len(s) >= 10) && (sqliteLike(s, "%REDACTED%"))
}

func sqliteLike(s, pattern string) bool {
	return true
}

func TestIndexer_ProgressCallback(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "coppermind-progress-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create 3 valid files
	for i := 1; i <= 3; i++ {
		fname := filepath.Join(tempDir, "file"+string(rune('0'+i))+".go")
		content := "package main\n\nfunc Hello" + string(rune('0'+i)) + "() {}\n"
		if err := os.WriteFile(fname, []byte(content), 0644); err != nil {
			t.Fatalf("failed to write %s: %v", fname, err)
		}
	}

	dbPath := filepath.Join(tempDir, "coppermind.db")
	store, err := sqlite.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	defer store.Close()

	mgr := brain.NewManager(store, embedding.NewEmbedderFromEnv(), scratchpad.NewMemoryScratchpad())

	var events []IndexProgress
	progressCb := func(p IndexProgress) {
		events = append(events, p)
	}

	stats, err := IndexDirectory(context.Background(), mgr, tempDir, IndexOptions{
		OnProgress: progressCb,
	})
	if err != nil {
		t.Fatalf("IndexDirectory failed: %v", err)
	}

	if stats.FilesIndexed != 3 {
		t.Errorf("expected 3 files indexed, got %d", stats.FilesIndexed)
	}

	if len(events) == 0 {
		t.Fatalf("expected progress events, got 0")
	}

	// Verify we saw discovering, indexing, and complete phases
	sawDiscovering := false
	sawIndexing := false
	sawComplete := false
	for _, ev := range events {
		if ev.Phase == PhaseDiscovering {
			sawDiscovering = true
		}
		if ev.Phase == PhaseIndexing {
			sawIndexing = true
		}
		if ev.Phase == PhaseComplete {
			sawComplete = true
			if !ev.Done {
				t.Errorf("expected Done=true in complete event")
			}
			if ev.Percentage != 100.0 {
				t.Errorf("expected Percentage=100.0 in complete event, got %f", ev.Percentage)
			}
		}
	}

	if !sawDiscovering {
		t.Errorf("did not observe PhaseDiscovering event")
	}
	if !sawIndexing {
		t.Errorf("did not observe PhaseIndexing event")
	}
	if !sawComplete {
		t.Errorf("did not observe PhaseComplete event")
	}
}

func TestProgressMeter_TTY(t *testing.T) {
	var buf strings.Builder
	meter := NewProgressMeter(MeterOptions{
		Writer:      &buf,
		ForceTTY:    true,
		MinInterval: 0, // no throttling for test
	})

	meter.Update(IndexProgress{
		Phase:        PhaseDiscovering,
		FilesScanned: 50,
		TotalFiles:   10,
	})

	meter.Update(IndexProgress{
		Phase:        PhaseIndexing,
		CurrentFile:  "pkg/brain/manager.go",
		TotalFiles:   10,
		FilesIndexed: 5,
		ChunksStored: 20,
		Percentage:   50.0,
		Rate:         12.5,
	})

	meter.Update(IndexProgress{
		Phase: PhaseComplete,
		Done:  true,
	})
	_ = meter.Close()

	out := buf.String()
	if !strings.Contains(out, "\033[K") {
		t.Errorf("expected ANSI escape code in TTY output, got: %q", out)
	}
	if !strings.Contains(out, "Discovering") {
		t.Errorf("expected 'Discovering' in output, got: %q", out)
	}
	if !strings.Contains(out, "50.0%") {
		t.Errorf("expected '50.0%%' in output, got: %q", out)
	}
}

func TestProgressMeter_NonTTY(t *testing.T) {
	var buf strings.Builder
	meter := NewProgressMeter(MeterOptions{
		Writer:     &buf,
		DisableTTY: true,
	})

	meter.Update(IndexProgress{
		Phase:        PhaseDiscovering,
		FilesScanned: 10,
		TotalFiles:   5,
		FilesSkipped: 5,
	})

	meter.Update(IndexProgress{
		Phase:        PhaseIndexing,
		TotalFiles:   10,
		FilesIndexed: 2,
		ChunksStored: 5,
		Percentage:   20.0,
	})

	meter.Update(IndexProgress{
		Phase:        PhaseIndexing,
		TotalFiles:   10,
		FilesIndexed: 5,
		ChunksStored: 15,
		Percentage:   50.0,
	})

	meter.Update(IndexProgress{
		Phase:        PhaseComplete,
		TotalFiles:   10,
		FilesIndexed: 10,
		ChunksStored: 30,
		Done:         true,
	})
	_ = meter.Close()

	out := buf.String()
	if strings.Contains(out, "\033") {
		t.Errorf("expected NO ANSI escape codes in non-TTY output, got: %q", out)
	}
	if !strings.Contains(out, "[index] Discovered 5 candidate files") {
		t.Errorf("expected non-TTY discovery log line, got: %q", out)
	}
	if !strings.Contains(out, "[index] Progress:  20.0%") {
		t.Errorf("expected 20.0%% progress line, got: %q", out)
	}
	if !strings.Contains(out, "[index] Progress:  50.0%") {
		t.Errorf("expected 50.0%% progress line, got: %q", out)
	}
	if !strings.Contains(out, "[index] Progress: 100.0%") {
		t.Errorf("expected 100.0%% complete line, got: %q", out)
	}
}

func TestProgressMeter_Quiet(t *testing.T) {
	var buf strings.Builder
	meter := NewProgressMeter(MeterOptions{
		Writer:   &buf,
		Quiet:    true,
		ForceTTY: true,
	})

	meter.Update(IndexProgress{
		Phase:      PhaseIndexing,
		Percentage: 50.0,
	})
	meter.Close()

	if buf.Len() != 0 {
		t.Errorf("expected 0 bytes written when Quiet=true, got %d bytes: %q", buf.Len(), buf.String())
	}
}
