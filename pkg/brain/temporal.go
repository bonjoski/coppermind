package brain

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	relDurationRe = regexp.MustCompile(`^([1-9][0-9]{0,4})([hdm])$`)
	gitRefSafeRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,63}$`)
)

// ParseTemporalBound strictly parses a relative duration (e.g. "24h", "7d", "30m"),
// natural alias ("today", "yesterday", "last-week", "last-month"),
// or absolute timestamp (RFC3339 or YYYY-MM-DD) relative to now.
// Fails closed on malformed inputs.
func ParseTemporalBound(raw string, now time.Time) (time.Time, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return time.Time{}, fmt.Errorf("temporal bound cannot be empty")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	switch strings.ToLower(s) {
	case "today":
		y, m, d := now.UTC().Date()
		return time.Date(y, m, d, 0, 0, 0, 0, time.UTC), nil
	case "yesterday":
		return now.UTC().Add(-24 * time.Hour), nil
	case "last-week", "last_week":
		return now.UTC().Add(-7 * 24 * time.Hour), nil
	case "last-month", "last_month":
		return now.UTC().Add(-30 * 24 * time.Hour), nil
	}

	if m := relDurationRe.FindStringSubmatch(strings.ToLower(s)); len(m) == 3 {
		val, err := strconv.Atoi(m[1])
		if err != nil || val <= 0 {
			return time.Time{}, fmt.Errorf("invalid relative duration %q", raw)
		}
		switch m[2] {
		case "m":
			return now.Add(-time.Duration(val) * time.Minute), nil
		case "h":
			return now.Add(-time.Duration(val) * time.Hour), nil
		case "d":
			return now.Add(-time.Duration(val) * 24 * time.Hour), nil
		}
	}

	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t.UTC(), nil
	}

	return time.Time{}, fmt.Errorf("invalid temporal bound %q (expected relative duration like 24h/7d/30m, alias like yesterday/last-week, YYYY-MM-DD, RFC3339, or git tag)", raw)
}

// ResolveTemporalBound extends ParseTemporalBound with local git tag/ref resolution
// (e.g. "--since v0.5.0" or "--since tag:v0.5.0"). Uses a strict ref allowlist and
// bounded 250ms exec with "--" argument separator; fails closed on injection or unknown refs.
func ResolveTemporalBound(raw, repoDir string, now time.Time) (time.Time, error) {
	if t, err := ParseTemporalBound(raw, now); err == nil {
		return t, nil
	}
	s := strings.TrimSpace(raw)
	if s == "" {
		return time.Time{}, fmt.Errorf("temporal bound cannot be empty")
	}
	ref := strings.TrimPrefix(s, "tag:")
	if !IsSafeGitRef(ref) {
		return time.Time{}, fmt.Errorf("invalid temporal bound or unsafe git ref %q", raw)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	var args []string
	if strings.TrimSpace(repoDir) != "" {
		args = append(args, "-C", repoDir)
	}
	args = append(args, "log", "-1", "--format=%cI", ref, "--")
	out, err := exec.CommandContext(ctx, "git", args...).Output()
	if err != nil {
		return time.Time{}, fmt.Errorf("failed resolving temporal bound or git tag %q (expected duration, YYYY-MM-DD, RFC3339, or valid local git ref)", raw)
	}
	tsStr := strings.TrimSpace(string(out))
	t, err := time.Parse(time.RFC3339, tsStr)
	if err != nil {
		return time.Time{}, fmt.Errorf("unexpected git timestamp %q for ref %q: %w", tsStr, ref, err)
	}
	return t.UTC(), nil
}

// IsSafeGitRef validates a git tag/ref against flag injection, path traversal, and shell metacharacters.
func IsSafeGitRef(ref string) bool {
	if !gitRefSafeRe.MatchString(ref) {
		return false
	}
	if strings.Contains(ref, "..") || strings.Contains(ref, "@{") || strings.HasSuffix(ref, "/") || strings.HasSuffix(ref, ".lock") {
		return false
	}
	return true
}
