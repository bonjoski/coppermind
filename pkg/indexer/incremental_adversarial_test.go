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

func TestASTChunking_GoSymbolsAndMarkdownFences(t *testing.T) {
	goSrc := []byte(`package demo

// Greeter says hello.
type Greeter struct {
	Name string
}

// Greet formats a greeting.
func (g *Greeter) Greet() string {
	return "hi " + g.Name
}
`)
	chunks := ChunkSource("pkg/demo/greeter.go", ".go", goSrc, 50, 5)
	if len(chunks) != 2 {
		t.Fatalf("expected 2 Go AST chunks (type + method), got %d", len(chunks))
	}
	if chunks[0].Symbol != "demo.Greeter" || chunks[1].Symbol != "Greeter.Greet" {
		t.Fatalf("unexpected AST symbols: %+v", chunks)
	}

	// Markdown heading-tree must NOT split inside fenced code blocks even with # comments
	mdSrc := []byte("# Title\n\n## Setup\n\n```sh\n# not a heading\necho hi\n```\n\n## Usage\nRun it.\n")
	mdChunks := ChunkSource("README.md", ".md", mdSrc, 60, 5)
	if len(mdChunks) < 2 {
		t.Fatalf("expected >=2 markdown sections, got %d", len(mdChunks))
	}
	for _, c := range mdChunks {
		if strings.Contains(c.Content, "echo hi") && !strings.Contains(c.Content, "```sh") {
			t.Fatalf("markdown chunker split inside fenced code block: %s", c.Content)
		}
	}
}

func TestAdversarial_IncrementalIndexerSymlinkSyntaxAndMerkleIntegrity(t *testing.T) {
	workDir := t.TempDir()
	outsideDir := t.TempDir()
	dbPath := filepath.Join(t.TempDir(), "inc.db")

	store, err := sqlite.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()
	mgr := brain.NewManager(store, embedding.NewLocalHashEmbedder(128), scratchpad.NewMemoryScratchpad())
	defer mgr.Close()

	// 1. Seed an episodic conversational session BEFORE indexing to verify Merkle chain survival!
	if _, err := mgr.Remember(ctx, brain.RememberRequest{
		SessionID:  "episodic-session",
		Category:   "decision",
		Content:    "Episodic decision 1: keep Merkle chains isolated from mutable code indices.",
		Provenance: brain.ProvenanceLocalWorkspace,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Remember(ctx, brain.RememberRequest{
		SessionID:  "episodic-session",
		Category:   "decision",
		Content:    "Episodic decision 2: prune deleted source chunks cleanly.",
		Provenance: brain.ProvenanceLocalWorkspace,
	}); err != nil {
		t.Fatal(err)
	}

	// 2. Create workspace files: valid Go, syntax-broken Go, and symlink escape targeting outside secret
	outsideSecret := filepath.Join(outsideDir, "secret.txt")
	_ = os.WriteFile(outsideSecret, []byte("TOP_SECRET_OUTSIDE_WORKSPACE_MARKER"), 0600)

	mainGo := filepath.Join(workDir, "main.go")
	_ = os.WriteFile(mainGo, []byte("package main\n\nfunc Hello() string { return \"hello-v1\" }\n"), 0644)

	brokenGo := filepath.Join(workDir, "broken.go")
	_ = os.WriteFile(brokenGo, []byte("package broken\nfunc ((( malformed syntax\n"), 0644)

	symlinkEscape := filepath.Join(workDir, "escape.go")
	_ = os.Symlink(outsideSecret, symlinkEscape)

	// Run 1: Initial index
	stats1, err := IndexDirectory(ctx, mgr, workDir, IndexOptions{})
	if err != nil {
		t.Fatalf("initial IndexDirectory failed: %v", err)
	}
	if stats1.FilesIndexed != 2 || stats1.ChunksStored < 2 {
		t.Fatalf("expected 2 indexed files (main.go + fallback broken.go), got %+v", stats1)
	}

	// Verify symlink escape content NEVER entered Coppermind!
	resSecret, _ := mgr.Recall(ctx, brain.RecallRequest{Query: "TOP_SECRET_OUTSIDE_WORKSPACE_MARKER", Hybrid: true, Limit: 5})
	for _, r := range resSecret {
		if strings.Contains(r.Node.Content, "TOP_SECRET_OUTSIDE_WORKSPACE_MARKER") {
			t.Fatalf("SECURITY VIOLATION: symlink escape file was indexed into memory")
		}
	}

	// Run 2: Incremental re-index with zero changes MUST skip all unchanged files
	stats2, err := IndexDirectory(ctx, mgr, workDir, IndexOptions{})
	if err != nil {
		t.Fatalf("second IndexDirectory failed: %v", err)
	}
	if stats2.FilesIndexed != 0 || stats2.FilesUnchanged != 2 {
		t.Fatalf("expected 0 indexed and 2 unchanged on incremental re-run, got %+v", stats2)
	}

	// Run 3: Modify main.go and delete broken.go -> stale chunks swapped & deleted file pruned
	_ = os.WriteFile(mainGo, []byte("package main\n\nfunc Hello() string { return \"hello-v2-updated\" }\n"), 0644)
	_ = os.Remove(brokenGo)

	stats3, err := IndexDirectory(ctx, mgr, workDir, IndexOptions{})
	if err != nil {
		t.Fatalf("third IndexDirectory failed: %v", err)
	}
	if stats3.FilesIndexed != 1 || stats3.FilesPruned != 1 || stats3.ChunksPruned < 2 {
		t.Fatalf("expected 1 modified + 1 pruned file with >=2 chunks pruned, got %+v", stats3)
	}

	// Verify episodic Merkle chain is 100% intact after code-index swaps & pruning!
	ok, count, badID, err := mgr.VerifySessionChain(ctx, "episodic-session")
	if err != nil || !ok || count != 2 {
		t.Fatalf("episodic Merkle chain corrupted after code-index pruning: ok=%v count=%d badID=%s err=%v", ok, count, badID, err)
	}
}
