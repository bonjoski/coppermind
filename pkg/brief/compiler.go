package brief

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/embedding"
	"github.com/bonjoski/coppermind/pkg/gitscope"
	"github.com/bonjoski/coppermind/pkg/lenses"
	"github.com/bonjoski/coppermind/pkg/storage/sqlite"
)

const (
	// HardMaxTokens enforces the strict <=800-token ceiling (~3,200 chars).
	HardMaxTokens = 800
	charsPerToken = 4
)

// BriefRequest configures deterministic live context compilation.
type BriefRequest struct {
	RepoDir      string   `json:"repo_dir,omitempty"`
	MaxTokens    int      `json:"max_tokens,omitempty"`
	TouchedFiles []string `json:"touched_files,omitempty"`
	Format       string   `json:"format,omitempty"` // "markdown" | "json"
}

// BriefResult captures the compiled token-budgeted project brief and latency metrics.
type BriefResult struct {
	Repo              string        `json:"repo"`
	Branch            string        `json:"branch"`
	TouchedFiles      []string      `json:"touched_files,omitempty"`
	InvariantsCount   int           `json:"invariants_count"`
	OpenAlertsCount   int           `json:"open_alerts_count"`
	PendingInboxCount int           `json:"pending_inbox_count"`
	DecisionsCount    int           `json:"decisions_count"`
	MentorNudgesCount int           `json:"mentor_nudges_count"`
	EstimatedTokens   int           `json:"estimated_tokens"`
	Duration          time.Duration `json:"duration"`
	Markdown          string        `json:"markdown"`
}

// Compile deterministically assembles a <=800-token 4-slot live project brief in <8ms
// with zero LLM calls and read-only SQLite WAL queries.
func Compile(ctx context.Context, mgr *brain.Manager, req BriefRequest) (*BriefResult, error) {
	start := time.Now()
	maxTokens := req.MaxTokens
	if maxTokens <= 0 || maxTokens > HardMaxTokens {
		maxTokens = HardMaxTokens
	}
	maxChars := maxTokens * charsPerToken

	repoDir := strings.TrimSpace(req.RepoDir)
	scope := gitscope.Detect(repoDir)
	repoName := scope.RepoName
	if repoName == "" && repoDir != "" {
		repoName = filepath.Base(repoDir)
	}
	if repoName == "" {
		repoName = "workspace"
	}
	branch := scope.Branch
	if branch == "" {
		branch = "main"
	}

	touched := req.TouchedFiles
	if len(touched) == 0 && scope.IsGit {
		touched = detectDirtyFiles(ctx, repoDir)
	}

	res := &BriefResult{
		Repo:         repoName,
		Branch:       branch,
		TouchedFiles: touched,
	}

	// Slot budgets (chars): 250 / 200 / 200 / 150 tokens = 1000 / 800 / 800 / 600 chars
	slot1Budget := (maxChars * 250) / 800
	slot2Budget := (maxChars * 200) / 800
	slot3Budget := (maxChars * 200) / 800
	slot4Budget := maxChars - slot1Budget - slot2Budget - slot3Budget

	var sqlStore *sqlite.SQLiteStore
	if mgr != nil && mgr.Store() != nil {
		sqlStore, _ = mgr.Store().(*sqlite.SQLiteStore)
	}

	// Slot 1: Touched-File TIER_0/TIER_1 Invariants (via 1-hop graph entity index)
	var slot1Lines []string
	if sqlStore != nil && len(touched) > 0 {
		seen := make(map[string]bool)
		for _, f := range touched {
			nodes, err := sqlStore.ImpactForFile(ctx, f, 5)
			if err != nil {
				continue
			}
			for _, n := range nodes {
				if seen[n.ID] || n.Derived {
					continue
				}
				if n.AuthorityTier != "TIER_0_SOVEREIGN" && n.AuthorityTier != "TIER_1_ARCHITECTURE" {
					continue
				}
				seen[n.ID] = true
				slot1Lines = append(slot1Lines, fmt.Sprintf("- [%s] (%s) %s", n.AuthorityTier, f, compactLine(n.Content, 160)))
				res.InvariantsCount++
				if len(slot1Lines) >= 5 {
					break
				}
			}
			if len(slot1Lines) >= 5 {
				break
			}
		}
	}
	if len(slot1Lines) == 0 && mgr != nil {
		// Fallback to active TIER_0/TIER_1 invariants for current repo
		recalled, _ := mgr.Recall(ctx, brain.RecallRequest{
			Query:         repoName + " architecture invariant security policy",
			AuthorityTier: "TIER_1_ARCHITECTURE",
			ActiveRepo:    repoName,
			ActiveBranch:  branch,
			Hybrid:        true,
			Limit:         3,
		})
		for _, r := range recalled {
			slot1Lines = append(slot1Lines, fmt.Sprintf("- [%s] %s", r.Node.AuthorityTier, compactLine(r.Node.Content, 160)))
			res.InvariantsCount++
		}
	}

	// Slot 2: Open High/Critical Observations + Pending Zero-Key Lens Inbox
	var slot2Lines []string
	if mgr != nil {
		obs, _ := mgr.ListObservations(ctx, "", "", "open", "high", 4)
		res.OpenAlertsCount = len(obs)
		for _, o := range obs {
			slot2Lines = append(slot2Lines, fmt.Sprintf("- [%s/%s] %s", strings.ToUpper(o.Severity), o.SourceLens, compactLine(o.Content, 140)))
		}
	}
	if sqlStore != nil {
		tickets, _ := sqlStore.ListPendingTickets(ctx, "", "pending", 10)
		res.PendingInboxCount = len(tickets)
		if len(tickets) > 0 {
			slot2Lines = append(slot2Lines, fmt.Sprintf("- [INBOX] %d pending commit lens ticket(s); oldest (%s): %s",
				len(tickets), tickets[0].LensName, compactLine(tickets[0].Summary, 110)))
		}
	}

	// Slot 3: Recent Decisions & Dead-Ends on Repo/Branch
	var slot3Lines []string
	if mgr != nil {
		for _, cat := range []string{"dead_end", "decision"} {
			recalled, _ := mgr.Recall(ctx, brain.RecallRequest{
				Query:        repoName + " " + branch + " " + cat,
				Category:     cat,
				ActiveRepo:   repoName,
				ActiveBranch: branch,
				Hybrid:       true,
				Limit:        2,
			})
			for _, r := range recalled {
				tag := strings.ToUpper(r.Node.Category)
				slot3Lines = append(slot3Lines, fmt.Sprintf("- [%s] %s", tag, compactLine(r.Node.Content, 150)))
				res.DecisionsCount++
				if len(slot3Lines) >= 3 {
					break
				}
			}
			if len(slot3Lines) >= 3 {
				break
			}
		}
	}

	// Slot 4: Active Scratchpad Handoffs + <=2 Passive Mentor Nudges
	var slot4Lines []string
	if mgr != nil && mgr.Scratchpad() != nil {
		keys := mgr.Scratchpad().Keys(ctx)
		for _, k := range keys {
			if strings.HasPrefix(k, "handoff:") || k == "active_task" {
				if val, ok := mgr.Scratchpad().Get(ctx, k); ok {
					slot4Lines = append(slot4Lines, fmt.Sprintf("- [SCRATCHPAD:%s] %s", k, compactLine(val, 120)))
					if len(slot4Lines) >= 2 {
						break
					}
				}
			}
		}
	}
	if mgr != nil && mgr.Store() != nil {
		mentorQuery := repoName + " " + strings.Join(touched, " ")
		if strings.TrimSpace(mentorQuery) != "" {
			ml := lenses.NewSQLiteMentorLens(mgr.Store(), embedding.NewLocalHashEmbedder(128))
			if nudges, err := ml.MatchContext(ctx, mentorQuery, nil, 2); err == nil {
				for _, n := range nudges {
					slot4Lines = append(slot4Lines, fmt.Sprintf("- [MENTOR] %s: %s", n.Title, compactLine(n.SecureDefault, 110)))
					res.MentorNudgesCount++
				}
			}
		}
	}

	// Assemble with downward rollover and strict hard ceiling
	header := fmt.Sprintf("<coppermind_brief repo=%q branch=%q>\n", repoName, branch)
	footer := "</coppermind_brief>"
	avail := maxChars - len(header) - len(footer)
	if avail < 200 {
		avail = 200
	}

	sections := []struct {
		title  string
		lines  []string
		budget int
	}{
		{"## Invariants", slot1Lines, slot1Budget},
		{"## Alerts & Inbox", slot2Lines, slot2Budget},
		{"## Recent Decisions & Dead-Ends", slot3Lines, slot3Budget},
		{"## Active Handoffs & Mentor", slot4Lines, slot4Budget},
	}

	var body strings.Builder
	rollover := 0
	for _, sec := range sections {
		if len(sec.lines) == 0 {
			rollover += sec.budget
			continue
		}
		secBudget := sec.budget + rollover
		rollover = 0
		chunk := sec.title + "\n" + strings.Join(sec.lines, "\n") + "\n"
		if len(chunk) > secBudget {
			chunk = truncateBudget(chunk, secBudget)
		}
		if body.Len()+len(chunk) > avail {
			remaining := avail - body.Len()
			if remaining > 24 {
				body.WriteString(truncateBudget(chunk, remaining))
			}
			break
		}
		body.WriteString(chunk)
		if secBudget > len(chunk) {
			rollover += secBudget - len(chunk)
		}
	}

	if body.Len() == 0 {
		body.WriteString("No active invariants, alerts, or recent decisions matched this workspace.\n")
	}

	md := header + body.String() + footer
	if len(md) > maxChars {
		md = truncateBudget(md, maxChars-len(footer)) + footer
	}

	res.Markdown = md
	res.EstimatedTokens = (len(md) + charsPerToken - 1) / charsPerToken
	res.Duration = time.Since(start)
	return res, nil
}

// MarshalJSONOutput serializes the brief result as indented JSON.
func (r *BriefResult) MarshalJSONOutput() (string, error) {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func detectDirtyFiles(ctx context.Context, repoDir string) []string {
	tctx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(tctx, "git", "status", "--porcelain")
	if repoDir != "" {
		cmd.Dir = repoDir
	}
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	var files []string
	for _, line := range strings.Split(string(out), "\n") {
		if len(line) < 4 {
			continue
		}
		p := strings.TrimSpace(line[3:])
		if idx := strings.Index(p, " -> "); idx >= 0 {
			p = strings.TrimSpace(p[idx+4:])
		}
		if p != "" {
			files = append(files, filepath.ToSlash(p))
		}
		if len(files) >= 12 {
			break
		}
	}
	return files
}

func compactLine(s string, max int) string {
	clean := strings.Join(strings.Fields(s), " ")
	runes := []rune(clean)
	if len(runes) <= max {
		return clean
	}
	if max <= 3 {
		return string(runes[:max])
	}
	return strings.TrimSpace(string(runes[:max-3])) + "..."
}

func truncateBudget(s string, max int) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	if max <= 4 {
		return string(runes[:max])
	}
	return strings.TrimRight(string(runes[:max-4]), " \t") + "...\n"
}
