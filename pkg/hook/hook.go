package hook

import (
	"fmt"
	"os"
	"path/filepath"
)

const postCommitScript = `#!/bin/sh
# Coppermind automated episodic git commit capture hook
if command -v coppermind >/dev/null 2>&1; then
    COMMIT_HASH=$(git rev-parse HEAD 2>/dev/null)
    COMMIT_MSG=$(git log -1 --pretty=%B 2>/dev/null | head -n 1)
    COMMIT_AUTHOR=$(git log -1 --pretty=%an 2>/dev/null)
    REPO_NAME=$(basename "$(git rev-parse --show-toplevel 2>/dev/null)")
    if [ -n "$COMMIT_HASH" ]; then
        coppermind remember --session "$REPO_NAME" --category "git_commit" "Git commit $COMMIT_HASH by $COMMIT_AUTHOR: $COMMIT_MSG" >/dev/null 2>&1 &
    fi
fi
`

// InstallGitHook writes the post-commit hook into repoRoot/.git/hooks/post-commit.
func InstallGitHook(repoRoot string) (string, error) {
	gitDir := filepath.Join(repoRoot, ".git")
	if info, err := os.Stat(gitDir); err != nil || !info.IsDir() {
		return "", fmt.Errorf("%s is not a valid git repository (.git folder not found)", repoRoot)
	}

	hooksDir := filepath.Join(gitDir, "hooks")
	_ = os.MkdirAll(hooksDir, 0755)

	hookPath := filepath.Join(hooksDir, "post-commit")
	if err := os.WriteFile(hookPath, []byte(postCommitScript), 0755); err != nil {
		return "", fmt.Errorf("failed to write hook file: %w", err)
	}

	return hookPath, nil
}
