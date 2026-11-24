package brain

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var relDurationRe = regexp.MustCompile(`^([1-9][0-9]{0,4})([hdm])$`)

// ParseTemporalBound strictly parses a relative duration (e.g. "24h", "7d", "30m")
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

	return time.Time{}, fmt.Errorf("invalid temporal bound %q (expected relative duration like 24h/7d/30m, YYYY-MM-DD, or RFC3339)", raw)
}
