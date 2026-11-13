package hook

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const hookMarkerStart = "# >>> coppermind episodic capture hook >>>"
const hookMarkerEnd = "# <<< coppermind episodic capture hook <<<"

const hookPayload = `# >>> coppermind episodic capture hook >>>
if command -v coppermind >/dev/null 2>&1; then
    COMMIT_HASH=$(git rev-parse HEAD 2>/dev/null)
    COMMIT_MSG=$(git log -1 --pretty=%B 2>/dev/null | head -n 1)
    COMMIT_AUTHOR=$(git log -1 --pretty=%an 2>/dev/null)
    REPO_NAME=$(basename "$(git rev-parse --show-toplevel 2>/dev/null)")
    BRANCH_NAME=$(git rev-parse --abbrev-ref HEAD 2>/dev/null)
    if [ -n "$COMMIT_HASH" ]; then
        coppermind remember \
            --session "$REPO_NAME" \
            --category "git_commit" \
            "Git commit $COMMIT_HASH on branch '$BRANCH_NAME' by $COMMIT_AUTHOR: $COMMIT_MSG" >/dev/null 2>&1 &
    fi
fi
# <<< coppermind episodic capture hook <<<
`

// ResolveHooksDir finds the hooks directory for either a standard git repository or a worktree.
func ResolveHooksDir(repoRoot string) (string, error) {
	gitEntry := filepath.Join(repoRoot, ".git")
	info, err := os.Stat(gitEntry)
	if err != nil {
		return "", fmt.Errorf("%s is not a valid git repository (.git not found): %w", repoRoot, err)
	}

	if info.IsDir() {
		return filepath.Join(gitEntry, "hooks"), nil
	}

	// In git worktrees or submodules, .git is a text file pointing to gitdir: <path>
	content, err := os.ReadFile(gitEntry)
	if err != nil {
		return "", fmt.Errorf("failed to read .git file at %s: %w", gitEntry, err)
	}

	for _, line := range strings.Split(string(content), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "gitdir:") {
			gitdir := strings.TrimSpace(strings.TrimPrefix(trimmed, "gitdir:"))
			if !filepath.IsAbs(gitdir) {
				gitdir = filepath.Join(repoRoot, gitdir)
			}
			commondirFile := filepath.Join(gitdir, "commondir")
			if cdata, err := os.ReadFile(commondirFile); err == nil {
				cdir := strings.TrimSpace(string(cdata))
				if !filepath.IsAbs(cdir) {
					cdir = filepath.Join(gitdir, cdir)
				}
				return filepath.Join(cdir, "hooks"), nil
			}
			return filepath.Join(gitdir, "hooks"), nil
		}
	}

	return "", fmt.Errorf(".git file at %s does not contain valid gitdir reference", gitEntry)
}

// InstallGitHook writes or appends the post-commit hook safely.
func InstallGitHook(repoRoot string) (string, error) {
	hooksDir, err := ResolveHooksDir(repoRoot)
	if err != nil {
		return "", err
	}

	if err := os.MkdirAll(hooksDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create hooks directory: %w", err)
	}

	hookPath := filepath.Join(hooksDir, "post-commit")
	existing, err := os.ReadFile(hookPath)
	if err != nil {
		content := "#!/bin/sh\n\n" + hookPayload
		if err := os.WriteFile(hookPath, []byte(content), 0755); err != nil {
			return "", fmt.Errorf("failed to write hook file: %w", err)
		}
		return hookPath, nil
	}

	str := string(existing)
	if strings.Contains(str, hookMarkerStart) {
		start := strings.Index(str, hookMarkerStart)
		end := strings.Index(str, hookMarkerEnd)
		if end != -1 {
			end += len(hookMarkerEnd)
			str = str[:start] + strings.TrimSpace(hookPayload) + str[end:]
		}
	} else {
		if !strings.HasPrefix(str, "#!") {
			str = "#!/bin/sh\n\n" + str
		}
		str = strings.TrimRight(str, "\n") + "\n\n" + hookPayload
	}

	if err := os.WriteFile(hookPath, []byte(str), 0755); err != nil {
		return "", fmt.Errorf("failed to update hook file: %w", err)
	}

	return hookPath, nil
}

// UninstallGitHook removes Coppermind hooks from post-commit.
func UninstallGitHook(repoRoot string) error {
	hooksDir, err := ResolveHooksDir(repoRoot)
	if err != nil {
		return err
	}

	hookPath := filepath.Join(hooksDir, "post-commit")
	existing, err := os.ReadFile(hookPath)
	if err != nil {
		return nil
	}

	str := string(existing)
	if !strings.Contains(str, hookMarkerStart) {
		return nil
	}

	start := strings.Index(str, hookMarkerStart)
	end := strings.Index(str, hookMarkerEnd)
	if end != -1 {
		end += len(hookMarkerEnd)
		cleaned := strings.TrimSpace(str[:start] + str[end:])
		if cleaned == "" || cleaned == "#!/bin/sh" {
			_ = os.Remove(hookPath)
		} else {
			_ = os.WriteFile(hookPath, []byte(cleaned+"\n"), 0755)
		}
	}

	return nil
}

// StatusGitHook returns whether the hook is installed.
func StatusGitHook(repoRoot string) (bool, error) {
	hooksDir, err := ResolveHooksDir(repoRoot)
	if err != nil {
		return false, err
	}

	hookPath := filepath.Join(hooksDir, "post-commit")
	data, err := os.ReadFile(hookPath)
	if err != nil {
		return false, nil
	}

	return strings.Contains(string(data), hookMarkerStart), nil
}
