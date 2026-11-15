package doctor

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/bonjoski/coppermind/pkg/storage/sqlite"
)

func TestDoctor_11Pillars(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	dbPath := filepath.Join(tmpDir, "coppermind.db")
	store, err := sqlite.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to init store: %v", err)
	}
	defer store.Close()

	results := RunDiagnostics(ctx, tmpDir)
	if len(results) != 11 {
		t.Fatalf("expected 11 diagnostic pillars, got %d", len(results))
	}

	for _, p := range results {
		if p.Status == StatusFail {
			t.Errorf("diagnostic pillar failed: %s - %s", p.Name, p.Message)
		}
	}
}
