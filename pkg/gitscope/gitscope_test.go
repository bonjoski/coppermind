package gitscope_test

import (
	"testing"

	"github.com/bonjoski/coppermind/pkg/gitscope"
)

func TestDetect_InGitRepo(t *testing.T) {
	ctx := gitscope.Detect(".")
	if !ctx.IsGit {
		t.Fatalf("expected current directory to be detected as a git repository")
	}
	if ctx.RepoName != "coppermind" {
		t.Errorf("expected RepoName 'coppermind', got %q", ctx.RepoName)
	}
	if ctx.Branch == "" {
		t.Errorf("expected non-empty branch")
	}
	if len(ctx.Commit) < 7 {
		t.Errorf("expected valid commit SHA, got %q", ctx.Commit)
	}
}

func TestDetect_NonGitDirectory(t *testing.T) {
	tmp := t.TempDir()
	ctx := gitscope.Detect(tmp)
	if ctx.IsGit {
		t.Errorf("expected temp directory to not be a git repository")
	}
}
