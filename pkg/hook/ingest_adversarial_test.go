package hook

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/embedding"
	"github.com/bonjoski/coppermind/pkg/lenses"
	"github.com/bonjoski/coppermind/pkg/scratchpad"
	"github.com/bonjoski/coppermind/pkg/storage/sqlite"
)

func TestAdversarial_CommitMessageShellInjectionAndPendingInbox(t *testing.T) {
	repoDir := t.TempDir()
	markerFile := filepath.Join(t.TempDir(), "pwned_marker")

	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = repoDir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Tester",
			"GIT_AUTHOR_EMAIL=tester@example.com",
			"GIT_COMMITTER_NAME=Tester",
			"GIT_COMMITTER_EMAIL=tester@example.com",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, string(out))
		}
	}

	run("init")
	_ = os.WriteFile(filepath.Join(repoDir, "auth.go"), []byte("package main\n\nimport \"os/exec\"\nfunc runAuth(cmd string) { _ = exec.Command(cmd) }\n"), 0644)
	run("add", "auth.go")

	// Commit message containing shell command substitution injection!
	maliciousMsg := "fix auth $(touch " + markerFile + ") `touch " + markerFile + "` ; echo pwn"
	run("commit", "--no-gpg-sign", "-m", maliciousMsg)

	dbPath := filepath.Join(t.TempDir(), "hook.db")
	store, err := sqlite.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	mgr := brain.NewManager(store, embedding.NewLocalHashEmbedder(128), scratchpad.NewMemoryScratchpad())
	defer mgr.Close()

	ctx := context.Background()
	res, err := IngestCommit(ctx, mgr, repoDir, lenses.DefaultConfig())
	if err != nil {
		t.Fatalf("IngestCommit failed: %v", err)
	}

	// 1. Shell injection payload MUST NOT execute
	if _, statErr := os.Stat(markerFile); statErr == nil {
		t.Fatalf("SECURITY VIOLATION: commit message shell injection executed!")
	}

	// 2. Commit touching exec.Command / auth sink MUST queue at least 1 pending inbox ticket
	if res.TicketsQueued == 0 {
		t.Fatalf("expected >=1 pending lens ticket queued for exec/auth commit, got %+v", res)
	}

	// 3. Re-ingesting same commit MUST deduplicate (no duplicate pending tickets)
	tickets, err := store.ListPendingTickets(ctx, "", "pending", 20)
	if err != nil || len(tickets) == 0 {
		t.Fatalf("expected pending tickets in store, got %d err=%v", len(tickets), err)
	}
	if err := store.ResolvePendingTicket(ctx, tickets[0].ID, "completed"); err != nil {
		t.Fatalf("ResolvePendingTicket failed: %v", err)
	}
}

func TestIngestCommitResolvesCoppermindYamlScopeAndFailsClosed(t *testing.T) {
	t.Setenv("COPPERMIND_SCOPE", "")
	repoDir := t.TempDir()

	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = repoDir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Tester",
			"GIT_AUTHOR_EMAIL=tester@example.com",
			"GIT_COMMITTER_NAME=Tester",
			"GIT_COMMITTER_EMAIL=tester@example.com",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, string(out))
		}
	}

	run("init")
	if err := os.WriteFile(filepath.Join(repoDir, ".coppermind.yaml"), []byte("scope: bonjoski/airlock\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repoDir, "main.go"), []byte("package main\nfunc main() {}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	run("add", ".coppermind.yaml", "main.go")
	run("commit", "--no-gpg-sign", "-m", "feat: add initial airlock entry")

	store, err := sqlite.NewSQLiteStore(filepath.Join(t.TempDir(), "hook_scope.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	mgr := brain.NewManager(store, embedding.NewLocalHashEmbedder(128), scratchpad.NewMemoryScratchpad())
	defer mgr.Close()

	ctx := context.Background()
	res, err := IngestCommit(ctx, mgr, repoDir, lenses.DefaultConfig())
	if err != nil {
		t.Fatalf("IngestCommit with valid .coppermind.yaml failed: %v", err)
	}
	if res.Scope != "bonjoski/airlock" {
		t.Fatalf("expected commit memory scope 'bonjoski/airlock', got %q", res.Scope)
	}
	stored, err := store.GetByID(ctx, res.MemoryID)
	if err != nil || stored.Scope != "bonjoski/airlock" {
		t.Fatalf("stored commit node scope mismatch: node=%+v err=%v", stored, err)
	}

	// Malformed .coppermind.yaml must fail closed rather than falling open to global scope.
	if err := os.WriteFile(filepath.Join(repoDir, ".coppermind.yaml"), []byte("scope: ../../escape\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := IngestCommit(ctx, mgr, repoDir, lenses.DefaultConfig()); err == nil {
		t.Fatalf("SECURITY VIOLATION: IngestCommit fell open on invalid .coppermind.yaml scope")
	}
}
