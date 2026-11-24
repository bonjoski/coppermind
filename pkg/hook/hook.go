package hook

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const hookMarkerStart = "# >>> coppermind episodic capture hook >>>"
const hookMarkerEnd = "# <<< coppermind episodic capture hook <<<"

const mergeHookMarkerStart = "# >>> coppermind episodic diff integrity hook >>>"
const mergeHookMarkerEnd = "# <<< coppermind episodic diff integrity hook <<<"

const hookPayload = `# >>> coppermind episodic capture hook >>>
if command -v coppermind >/dev/null 2>&1; then
    REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null)
    if [ -n "$REPO_ROOT" ]; then
        coppermind hook ingest-commit --repo "$REPO_ROOT" >/dev/null 2>&1 &
    fi
fi
# <<< coppermind episodic capture hook <<<
`

const mergeHookPayload = `# >>> coppermind episodic diff integrity hook >>>
if command -v coppermind >/dev/null 2>&1; then
    REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null)
    REPO_NAME=$(basename "$REPO_ROOT")
    if git rev-parse --verify ORIG_HEAD >/dev/null 2>&1; then
        coppermind hook verify-diff \
            --repo "$REPO_ROOT" \
            --ref "ORIG_HEAD..HEAD" \
            --session "$REPO_NAME" \
            --provenance "TAINT_SHARED_DOC" || true
    fi
fi
# <<< coppermind episodic diff integrity hook <<<
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

func upsertHookBlock(hookPath, markerStart, markerEnd, payload string) error {
	existing, err := os.ReadFile(hookPath)
	if err != nil {
		content := "#!/bin/sh\n\n" + payload
		if err := os.WriteFile(hookPath, []byte(content), 0755); err != nil {
			return fmt.Errorf("failed to write hook file: %w", err)
		}
		return nil
	}

	str := string(existing)
	if strings.Contains(str, markerStart) {
		start := strings.Index(str, markerStart)
		end := strings.Index(str, markerEnd)
		if end != -1 {
			end += len(markerEnd)
			str = str[:start] + strings.TrimSpace(payload) + str[end:]
		}
	} else {
		if !strings.HasPrefix(str, "#!") {
			str = "#!/bin/sh\n\n" + str
		}
		str = strings.TrimRight(str, "\n") + "\n\n" + payload
	}

	if err := os.WriteFile(hookPath, []byte(str), 0755); err != nil {
		return fmt.Errorf("failed to update hook file: %w", err)
	}
	return nil
}

func removeHookBlock(hookPath, markerStart, markerEnd string) error {
	existing, err := os.ReadFile(hookPath)
	if err != nil {
		return nil
	}

	str := string(existing)
	if !strings.Contains(str, markerStart) {
		return nil
	}

	start := strings.Index(str, markerStart)
	end := strings.Index(str, markerEnd)
	if end != -1 {
		end += len(markerEnd)
		cleaned := strings.TrimSpace(str[:start] + str[end:])
		if cleaned == "" || cleaned == "#!/bin/sh" {
			_ = os.Remove(hookPath)
		} else {
			_ = os.WriteFile(hookPath, []byte(cleaned+"\n"), 0755)
		}
	}
	return nil
}

// InstallGitHook writes or appends the episodic capture (post-commit) and third-party
// diff integrity verification (post-merge) hooks safely.
func InstallGitHook(repoRoot string) (string, error) {
	hooksDir, err := ResolveHooksDir(repoRoot)
	if err != nil {
		return "", err
	}

	if err := os.MkdirAll(hooksDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create hooks directory: %w", err)
	}

	postCommitPath := filepath.Join(hooksDir, "post-commit")
	if err := upsertHookBlock(postCommitPath, hookMarkerStart, hookMarkerEnd, hookPayload); err != nil {
		return "", err
	}

	postMergePath := filepath.Join(hooksDir, "post-merge")
	if err := upsertHookBlock(postMergePath, mergeHookMarkerStart, mergeHookMarkerEnd, mergeHookPayload); err != nil {
		return "", err
	}

	return postCommitPath, nil
}

// UninstallGitHook removes Coppermind hooks from post-commit and post-merge.
func UninstallGitHook(repoRoot string) error {
	hooksDir, err := ResolveHooksDir(repoRoot)
	if err != nil {
		return err
	}

	if err := removeHookBlock(filepath.Join(hooksDir, "post-commit"), hookMarkerStart, hookMarkerEnd); err != nil {
		return err
	}
	return removeHookBlock(filepath.Join(hooksDir, "post-merge"), mergeHookMarkerStart, mergeHookMarkerEnd)
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
