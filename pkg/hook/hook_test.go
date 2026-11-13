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
}
