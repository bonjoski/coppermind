package hook

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallGitHook(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Without .git, should fail
	_, err := InstallGitHook(tmpDir)
	if err == nil {
		t.Fatalf("expected error installing in non-git directory, got nil")
	}

	// 2. With .git directory, should succeed
	gitDir := filepath.Join(tmpDir, ".git")
	if err := os.Mkdir(gitDir, 0755); err != nil {
		t.Fatalf("failed to create fake .git dir: %v", err)
	}

	hookPath, err := InstallGitHook(tmpDir)
	if err != nil {
		t.Fatalf("InstallGitHook failed: %v", err)
	}

	data, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatalf("failed to read written hook: %v", err)
	}

	if !strings.Contains(string(data), "coppermind remember") {
		t.Errorf("hook content does not contain coppermind remember command")
	}

	// Verify file permissions (must be executable 0755)
	info, err := os.Stat(hookPath)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if info.Mode()&0111 == 0 {
		t.Errorf("hook file is not executable: mode=%v", info.Mode())
	}

	// 3. Status check
	installed, err := StatusGitHook(tmpDir)
	if err != nil || !installed {
		t.Fatalf("expected StatusGitHook to report true, got %v (err: %v)", installed, err)
	}

	// 4. Uninstall check
	if err := UninstallGitHook(tmpDir); err != nil {
		t.Fatalf("UninstallGitHook failed: %v", err)
	}

	installed, _ = StatusGitHook(tmpDir)
	if installed {
		t.Errorf("expected hook to be uninstalled")
	}
}

func TestGitHook_PreservesExistingUserHooks(t *testing.T) {
	tmpDir := t.TempDir()
	gitDir := filepath.Join(tmpDir, ".git")
	hooksDir := filepath.Join(gitDir, "hooks")
	_ = os.MkdirAll(hooksDir, 0755)

	existingScript := "#!/bin/sh\necho 'running custom corporate telemetry'\n"
	hookPath := filepath.Join(hooksDir, "post-commit")
	if err := os.WriteFile(hookPath, []byte(existingScript), 0755); err != nil {
		t.Fatalf("failed to write custom hook: %v", err)
	}

	// Install coppermind hook - should append without erasing custom script
	if _, err := InstallGitHook(tmpDir); err != nil {
		t.Fatalf("InstallGitHook failed: %v", err)
	}

	content, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatalf("failed to read hook: %v", err)
	}
	str := string(content)
	if !strings.Contains(str, "running custom corporate telemetry") {
		t.Errorf("custom script was erased during install!")
	}
	if !strings.Contains(str, "coppermind remember") {
		t.Errorf("coppermind hook was not appended!")
	}

	// Uninstall coppermind hook - should restore custom script
	if err := UninstallGitHook(tmpDir); err != nil {
		t.Fatalf("UninstallGitHook failed: %v", err)
	}

	restored, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatalf("custom hook file was deleted during uninstall: %v", err)
	}
	if !strings.Contains(string(restored), "running custom corporate telemetry") {
		t.Errorf("custom script was not preserved after uninstall: %s", string(restored))
	}
	if strings.Contains(string(restored), "coppermind remember") {
		t.Errorf("coppermind hook was not removed after uninstall!")
	}
}

func TestGitHook_WorktreeSupport(t *testing.T) {
	tmpDir := t.TempDir()
	mainGitDir := filepath.Join(tmpDir, "main_repo", ".git")
	_ = os.MkdirAll(filepath.Join(mainGitDir, "worktrees", "wt1"), 0755)

	worktreeDir := filepath.Join(tmpDir, "worktrees", "wt1")
	_ = os.MkdirAll(worktreeDir, 0755)

	// .git file in worktree
	gitFile := filepath.Join(worktreeDir, ".git")
	targetGitDir := filepath.Join(mainGitDir, "worktrees", "wt1")
	_ = os.WriteFile(gitFile, []byte("gitdir: "+targetGitDir+"\n"), 0644)

	// In gitdir, commondir points to main .git
	commondirFile := filepath.Join(targetGitDir, "commondir")
	_ = os.WriteFile(commondirFile, []byte("../..\n"), 0644)

	hookPath, err := InstallGitHook(worktreeDir)
	if err != nil {
		t.Fatalf("InstallGitHook on worktree failed: %v", err)
	}

	if !strings.Contains(hookPath, filepath.Join("main_repo", ".git", "hooks")) {
		t.Errorf("hook was not installed in main repo commondir hooks: %s", hookPath)
	}
}
