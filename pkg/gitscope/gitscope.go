package gitscope

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"strings"
)

// GitContext encapsulates detected git repository context.
type GitContext struct {
	RepoName string
	RepoPath string
	Branch   string
	Commit   string
	IsGit    bool
}

// Detect inspects dir (or current directory if empty) for git repository metadata.
func Detect(dir string) GitContext {
	ctx := GitContext{IsGit: false}

	// 1. Get repository top-level directory
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	if dir != "" {
		cmd.Dir = dir
	}
	out, err := cmd.Output()
	if err != nil {
		return ctx
	}
	repoPath := strings.TrimSpace(string(out))
	if repoPath == "" {
		return ctx
	}

	ctx.IsGit = true
	ctx.RepoPath = repoPath
	ctx.RepoName = filepath.Base(repoPath)

	// 2. Get active branch or detached HEAD
	cmd = exec.Command("git", "branch", "--show-current")
	cmd.Dir = repoPath
	if out, err := cmd.Output(); err == nil && len(bytes.TrimSpace(out)) > 0 {
		ctx.Branch = strings.TrimSpace(string(out))
	} else {
		// Fallback for detached HEAD
		cmd = exec.Command("git", "rev-parse", "--abbrev-ref", "HEAD")
		cmd.Dir = repoPath
		if out, err := cmd.Output(); err == nil {
			ctx.Branch = strings.TrimSpace(string(out))
		}
	}

	// 3. Get latest commit SHA
	cmd = exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = repoPath
	if out, err := cmd.Output(); err == nil {
		ctx.Commit = strings.TrimSpace(string(out))
	}

	return ctx
}
