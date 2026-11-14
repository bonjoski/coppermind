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

func TestADV_IndexerSecurity(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "coppermind-adv-index-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "coppermind.db")
	store, err := sqlite.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	defer store.Close()

	embedder := embedding.NewEmbedderFromEnv()
	sp := scratchpad.NewMemoryScratchpad()
	mgr := brain.NewManager(store, embedder, sp)

	// ADV-1: Path traversal / invalid path must fail safely
	_, err = IndexDirectory(context.Background(), mgr, filepath.Join(tempDir, "non_existent_subdir_12345"), IndexOptions{})
	if err == nil {
		t.Errorf("expected error indexing non-existent directory, got nil")
	}

	// ADV-2: Sensitive private key block in file must be skipped or rejected without persisting raw key
	subDir := filepath.Join(tempDir, "code")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatalf("failed to create code dir: %v", err)
	}

	privKeyFile := filepath.Join(subDir, "deploy_key.pem")
	privKeyContent := `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y1+abcdefghijklmnopqrstuvwxyz1234567890
-----END RSA PRIVATE KEY-----`
	if err := os.WriteFile(privKeyFile, []byte(privKeyContent), 0600); err != nil {
		t.Fatalf("failed to write pem file: %v", err)
	}

	stats, err := IndexDirectory(context.Background(), mgr, subDir, IndexOptions{})
	if err != nil {
		t.Fatalf("IndexDirectory returned unexpected error: %v", err)
	}

	if stats.FilesIndexed != 0 {
		t.Errorf("expected 0 files indexed when dir only contains private key pem, got %d", stats.FilesIndexed)
	}

	// ADV-3: Ensure private key was NOT inserted into database
	results, err := mgr.Recall(context.Background(), brain.RecallRequest{
		Query: "PRIVATE KEY",
	})
	if err != nil {
		t.Fatalf("Recall failed: %v", err)
	}
	if len(results) > 0 {
		t.Errorf("critical security failure: private key found in memory store: %v", results[0].Node.Content)
	}
}

// ADV-4: Verify terminal injection vectors in filenames are neutralized by sanitizeTerminalString
func TestADV_ProgressTerminalInjectionSanitization(t *testing.T) {
	maliciousInputs := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "ANSI clear screen injection",
			input:    "malicious\033[2Jcode.go",
			expected: "malicious[2Jcode.go",
		},
		{
			name:     "Carriage return overwriting line",
			input:    "evil\r\ninnocent.go",
			expected: "evilinnocent.go",
		},
		{
			name:     "Cursor movement and escape seq",
			input:    "exploit\x1b[1;1H\x1b[?25l.go",
			expected: "exploit[1;1H[?25l.go",
		},
		{
			name:     "Null bytes and bell character",
			input:    "alert\x07\x00file.go",
			expected: "alertfile.go",
		},
	}

	for _, tc := range maliciousInputs {
		t.Run(tc.name, func(t *testing.T) {
			sanitized := sanitizeTerminalString(tc.input)
			if sanitized != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, sanitized)
			}
			// Must never contain any control byte < 0x20
			for _, r := range sanitized {
				if r < 0x20 {
					t.Fatalf("sanitized string still contains control byte 0x%02x: %s", r, sanitized)
				}
			}
		})
	}
}

// ADV-5: Stress-test multi-agent concurrent progress meter updates under N=8 parallel callers
func TestADV_ProgressMeterHighConcurrency(t *testing.T) {
	var buf strings.Builder
	meter := NewProgressMeter(MeterOptions{
		Writer:      &buf,
		ForceTTY:    true,
		MinInterval: 0,
	})

	const numGoroutines = 8
	const numUpdates = 200

	done := make(chan bool, numGoroutines)
	for g := 0; g < numGoroutines; g++ {
		go func(id int) {
			for i := 0; i < numUpdates; i++ {
				pct := float64(i) / float64(numUpdates) * 100.0
				meter.Update(IndexProgress{
					Phase:        PhaseIndexing,
					CurrentFile:  filepath.Join("pkg", "module.go"),
					TotalFiles:   numUpdates,
					FilesIndexed: i,
					ChunksStored: i * 2,
					Percentage:   pct,
				})
			}
			done <- true
		}(g)
	}

	for g := 0; g < numGoroutines; g++ {
		<-done
	}

	if err := meter.Close(); err != nil {
		t.Fatalf("failed to close meter: %v", err)
	}
}

// ADV-6: Empty directory must not trigger divide-by-zero or panic in progress calculations
func TestADV_ProgressEmptyDirectory(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "coppermind-empty-progress-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "coppermind.db")
	store, err := sqlite.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	defer store.Close()

	mgr := brain.NewManager(store, embedding.NewEmbedderFromEnv(), scratchpad.NewMemoryScratchpad())

	var captured []IndexProgress
	stats, err := IndexDirectory(context.Background(), mgr, tempDir, IndexOptions{
		OnProgress: func(p IndexProgress) {
			captured = append(captured, p)
		},
	})
	if err != nil {
		t.Fatalf("unexpected error on empty directory: %v", err)
	}

	if stats.FilesIndexed != 0 || stats.ChunksStored != 0 {
		t.Errorf("expected 0 files and 0 chunks, got %d files, %d chunks", stats.FilesIndexed, stats.ChunksStored)
	}

	// Verify complete event was cleanly emitted with 100%
	if len(captured) == 0 {
		t.Fatalf("expected progress events even on empty dir")
	}
	lastEvent := captured[len(captured)-1]
	if lastEvent.Phase != PhaseComplete || !lastEvent.Done {
		t.Errorf("expected final event to be PhaseComplete with Done=true, got %+v", lastEvent)
	}
}
