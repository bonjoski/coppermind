package hook

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/lenses"
	"github.com/bonjoski/coppermind/pkg/scope"
	"github.com/bonjoski/coppermind/pkg/security"
	"github.com/bonjoski/coppermind/pkg/storage"
)

const maxCommitDiffBytes = 4096

// IngestCommitResult summarizes a compiled, shell-free git commit ingestion run.
type IngestCommitResult struct {
	CommitSHA      string   `json:"commit_sha"`
	RepoName       string   `json:"repo_name"`
	BranchName     string   `json:"branch_name"`
	Scope          string   `json:"scope,omitempty"`
	MemoryID       string   `json:"memory_id"`
	Provenance     string   `json:"provenance"`
	TicketsQueued  int      `json:"tickets_queued"`
	MatchedLenses  []string `json:"matched_lenses,omitempty"`
	DiffQuarantine bool     `json:"diff_quarantine,omitempty"`
}

// IngestCommit captures HEAD commit metadata and bounded diff hunks via direct exec.Command
// (zero shell variable interpolation, immune to commit-message shell injection), verifies diff
// integrity via Stormcage, persists the episodic commit memory + graph edges, and enqueues
// zero-key pending lens review tickets when configured sink pre-filters match.
func IngestCommit(ctx context.Context, mgr *brain.Manager, repoRoot string, lensCfg *lenses.LensesConfig) (*IngestCommitResult, error) {
	if mgr == nil {
		return nil, fmt.Errorf("brain manager is required")
	}
	if strings.TrimSpace(repoRoot) == "" {
		top, err := runGit(ctx, "", "rev-parse", "--show-toplevel")
		if err != nil {
			return nil, fmt.Errorf("not inside a git repository: %w", err)
		}
		repoRoot = strings.TrimSpace(top)
	}

	commitSHA, err := runGit(ctx, repoRoot, "rev-parse", "HEAD")
	if err != nil || strings.TrimSpace(commitSHA) == "" {
		return nil, fmt.Errorf("failed reading HEAD commit: %w", err)
	}
	commitSHA = strings.TrimSpace(commitSHA)

	commitMsg, _ := runGit(ctx, repoRoot, "log", "-1", "--pretty=%s", commitSHA)
	commitAuthor, _ := runGit(ctx, repoRoot, "log", "-1", "--pretty=%an", commitSHA)
	sigValid, _ := runGit(ctx, repoRoot, "log", "-1", "--pretty=%G?", commitSHA)
	branchName, _ := runGit(ctx, repoRoot, "rev-parse", "--abbrev-ref", "HEAD")
	diffFiles, _ := runGit(ctx, repoRoot, "diff-tree", "--no-commit-id", "--name-status", "-r", commitSHA)
	diffPatch, _ := runGit(ctx, repoRoot, "show", "--no-color", "--unified=1", "--format=", commitSHA)

	commitMsg = strings.TrimSpace(commitMsg)
	commitAuthor = strings.TrimSpace(commitAuthor)
	branchName = strings.TrimSpace(branchName)
	repoName := filepath.Base(repoRoot)

	if len(diffPatch) > maxCommitDiffBytes {
		diffPatch = diffPatch[:maxCommitDiffBytes]
	}

	authorRole := "developer"
	prov := brain.ProvenanceSharedDoc
	isSigned := false
	if sig := strings.TrimSpace(sigValid); sig == "G" || sig == "U" {
		authorRole = "architect"
		prov = brain.ProvenanceLocalWorkspace
		isSigned = true
	}

	// 1. Stormcage embedded episodic diff integrity gate (v0.6.0 RFC-2026-11-24-54 invariant)
	if diffPatch != "" {
		if _, valErr := mgr.Validator().VerifyGitDiff(ctx, repoName, diffPatch, commitAuthor, isSigned, repoName, commitSHA); valErr != nil {
			return &IngestCommitResult{
				CommitSHA:      commitSHA,
				RepoName:       repoName,
				BranchName:     branchName,
				Provenance:     string(prov),
				DiffQuarantine: true,
			}, valErr
		}
	}

	// Sanitize bounded diff excerpt before persistence/pre-filtering
	sanitizedDiff := ""
	if diffPatch != "" {
		if secRes, sErr := security.SanitizeMemory(diffPatch); sErr == nil {
			sanitizedDiff = secRes.SanitizedText
		}
	}

	// Limit file list to 20 entries
	fileLines := strings.Split(strings.TrimSpace(diffFiles), "\n")
	if len(fileLines) > 20 {
		fileLines = fileLines[:20]
	}
	diffSummary := strings.Join(fileLines, "\n")

	content := fmt.Sprintf("Git commit %s on branch '%s' by %s: %s\nChanged files:\n%s",
		commitSHA, branchName, commitAuthor, commitMsg, diffSummary)
	if sanitizedDiff != "" {
		content += "\nDiff excerpt:\n" + sanitizedDiff
	}

	// Resolve hierarchical scope from COPPERMIND_SCOPE or repo-confined .coppermind.yaml (fail-closed on malformed manifest)
	resolvedScope, scErr := scope.Resolve("", repoRoot, repoRoot)
	if scErr != nil {
		return nil, fmt.Errorf("failed resolving commit scope for %s: %w", repoRoot, scErr)
	}

	node, err := mgr.Remember(ctx, brain.RememberRequest{
		SessionID:      repoName,
		Scope:          resolvedScope,
		Category:       "git_commit",
		Content:        content,
		Provenance:     prov,
		AuthorIdentity: commitAuthor,
		AuthorRole:     authorRole,
		Metadata: map[string]string{
			"git_repo":   repoName,
			"git_branch": branchName,
			"git_commit": commitSHA,
		},
	})
	if err != nil {
		return nil, err
	}

	res := &IngestCommitResult{
		CommitSHA:  commitSHA,
		RepoName:   repoName,
		BranchName: branchName,
		Scope:      node.Scope,
		MemoryID:   node.ID,
		Provenance: string(prov),
	}

	// 2. Zero-cost lens pre-filter -> Pending Lens Review Inbox (zero API keys / zero Ollama needed!)
	if lensCfg == nil {
		lensCfg = lenses.DefaultConfig()
	}
	if inboxStore, ok := mgr.Store().(storage.InboxStore); ok && lensCfg != nil {
		for i := range lensCfg.Lenses {
			lc := &lensCfg.Lenses[i]
			if lc.Name == "" {
				continue
			}
			_ = lc.Compile()
			if lc.PrefilterRegex != "" && !lc.MatchesPrefilter(content) {
				continue
			}
			// Only queue security/architecture/drift/red-team lenses with concrete prefilter hits
			if lc.PrefilterRegex == "" {
				continue
			}
			summary := fmt.Sprintf("Commit %.8s (%s): %s", commitSHA, branchName, commitMsg)
			if len(summary) > 180 {
				summary = summary[:177] + "..."
			}
			if qErr := inboxStore.EnqueuePendingTicket(ctx, storage.PendingLensTicket{
				LensName:     lc.Name,
				CommitSHA:    commitSHA,
				MemoryID:     node.ID,
				RepoName:     repoName,
				BranchName:   branchName,
				Summary:      summary,
				MatchedSinks: []string{lc.Name + "_prefilter"},
				Status:       "pending",
				CreatedAt:    time.Now(),
			}); qErr == nil {
				res.TicketsQueued++
				res.MatchedLenses = append(res.MatchedLenses, lc.Name)
			}
		}
	}

	return res, nil
}

func runGit(ctx context.Context, dir string, args ...string) (string, error) {
	tctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(tctx, "git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}
