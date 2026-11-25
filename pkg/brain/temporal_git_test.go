package brain

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestResolveTemporalBound_AliasesGitTagsAndAdversarialRefs(t *testing.T) {
	now := time.Date(2026, 11, 24, 15, 0, 0, 0, time.UTC)

	// 1. Natural aliases
	y, err := ParseTemporalBound("yesterday", now)
	if err != nil || !y.Equal(now.Add(-24*time.Hour)) {
		t.Fatalf("yesterday failed: %v %v", y, err)
	}
	lw, err := ParseTemporalBound("last-week", now)
	if err != nil || !lw.Equal(now.Add(-7*24*time.Hour)) {
		t.Fatalf("last-week failed: %v %v", lw, err)
	}
	lm, err := ParseTemporalBound("last-month", now)
	if err != nil || !lm.Equal(now.Add(-30*24*time.Hour)) {
		t.Fatalf("last-month failed: %v %v", lm, err)
	}

	// 2. Real local git tag resolution
	repo := t.TempDir()
	runGit := func(env []string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		cmd.Env = append(os.Environ(), env...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, string(out))
		}
	}
	runGit(nil, "init")
	runGit(nil, "config", "user.name", "Test")
	runGit(nil, "config", "user.email", "test@local")
	runGit(nil, "config", "commit.gpgsign", "false")
	if err := os.WriteFile(filepath.Join(repo, "README.md"), []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	runGit(nil, "add", "README.md")
	commitEnv := []string{
		"GIT_AUTHOR_DATE=2026-10-15T12:30:00Z",
		"GIT_COMMITTER_DATE=2026-10-15T12:30:00Z",
	}
	runGit(commitEnv, "commit", "-m", "init")
	runGit(commitEnv, "tag", "v0.5.0")

	resolved, err := ResolveTemporalBound("v0.5.0", repo, now)
	if err != nil {
		t.Fatalf("ResolveTemporalBound(v0.5.0) failed: %v", err)
	}
	want := time.Date(2026, 10, 15, 12, 30, 0, 0, time.UTC)
	if !resolved.Equal(want) {
		t.Fatalf("expected %v, got %v", want, resolved)
	}
	resolvedPrefixed, err := ResolveTemporalBound("tag:v0.5.0", repo, now)
	if err != nil || !resolvedPrefixed.Equal(want) {
		t.Fatalf("ResolveTemporalBound(tag:v0.5.0) failed: %v %v", resolvedPrefixed, err)
	}

	// 3. Adversarial ref injection probes MUST fail closed
	badRefs := []string{
		"--exec=id",
		"-c",
		"tag:--format=%H",
		"../etc/passwd",
		"v0.5.0;whoami",
		"v0.5.0$(id)",
		"v0.5.0`id`",
		"HEAD@{0}",
		"nonexistent-tag-xyz",
	}
	for _, bad := range badRefs {
		if _, err := ResolveTemporalBound(bad, repo, now); err == nil {
			t.Fatalf("SECURITY VIOLATION: adversarial ref %q was accepted", bad)
		}
	}
}
