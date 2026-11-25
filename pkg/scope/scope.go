package scope

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
)

const (
	// MaxDepth caps hierarchical scope nesting (e.g., a/b/c/d/e/f/g/h).
	MaxDepth = 8
	// MaxLength caps total canonical scope byte length.
	MaxLength = 128
	// MaxSegmentLength caps individual segment length.
	MaxSegmentLength = 32
)

var (
	// ErrInvalidScope indicates a malformed, oversized, or security-violating scope path.
	ErrInvalidScope = errors.New("invalid hierarchical scope")
	// ErrInvalidScopeMode indicates an unrecognized scope recall mode.
	ErrInvalidScopeMode = errors.New("invalid scope mode")
	// ErrCrossScopeSupersession prevents child-scope writes from tombstoning broader ancestor memories.
	ErrCrossScopeSupersession = errors.New("cross-scope supersession denied fail-closed")

	validSegmentRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)
)

// Mode controls how scope filtering matches candidate memories during recall or export.
type Mode string

const (
	// ModeAncestors matches vault-global (""), all ancestor scopes, and exact target scope.
	// Unrelated sibling branches and deeper descendants are excluded.
	ModeAncestors Mode = "ancestors"
	// ModeExact matches only memories tagged with the exact target scope.
	ModeExact Mode = "exact"
	// ModeSubtree matches the target scope and all of its descendants (target/*).
	ModeSubtree Mode = "subtree"
	// ModeLineage matches vault-global (""), ancestors, exact target, and descendants (excludes siblings).
	ModeLineage Mode = "lineage"
	// ModeAll disables hard scope filtering (vault-wide search) while retaining soft ScopeAffinity reranking.
	ModeAll Mode = "all"
)

// Normalize validates and canonicalizes a hierarchical scope path.
// Empty string "" is valid and represents the vault-global scope.
// Rejects leading/trailing '/', empty segments ('a//b'), '.', '..', backslashes,
// SQL wildcards ('%', '*'), control/ANSI bytes, non-ASCII confusables, depth > 8, or length > 128B.
func Normalize(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}

	// Fail closed on any non-ASCII rune (homoglyphs, zero-width spaces, fullwidth slashes)
	// or ASCII control characters (newlines, tabs, ESC/ANSI, NUL).
	for i := 0; i < len(raw); i++ {
		b := raw[i]
		if b < 0x20 || b >= 0x7f {
			return "", fmt.Errorf("%w: contains disallowed control or non-ASCII byte 0x%02x", ErrInvalidScope, b)
		}
	}

	trimmed := strings.Trim(raw, " ")
	if trimmed == "" {
		return "", nil
	}
	if len(trimmed) > MaxLength {
		return "", fmt.Errorf("%w: length %d exceeds max %d bytes", ErrInvalidScope, len(trimmed), MaxLength)
	}
	if strings.ContainsAny(trimmed, "\\*%?'\"<>|; \t\r\n") {
		return "", fmt.Errorf("%w: %q contains prohibited characters", ErrInvalidScope, trimmed)
	}
	if strings.HasPrefix(trimmed, "/") || strings.HasSuffix(trimmed, "/") || strings.Contains(trimmed, "//") {
		return "", fmt.Errorf("%w: %q must not have leading, trailing, or empty slash segments", ErrInvalidScope, trimmed)
	}

	parts := strings.Split(trimmed, "/")
	if len(parts) > MaxDepth {
		return "", fmt.Errorf("%w: depth %d exceeds max %d segments", ErrInvalidScope, len(parts), MaxDepth)
	}

	normParts := make([]string, len(parts))
	for i, seg := range parts {
		lower := strings.ToLower(seg)
		if lower == "." || lower == ".." || len(lower) > MaxSegmentLength || !validSegmentRe.MatchString(lower) {
			return "", fmt.Errorf("%w: invalid segment %q (must match %s)", ErrInvalidScope, seg, validSegmentRe.String())
		}
		normParts[i] = lower
	}

	return strings.Join(normParts, "/"), nil
}

// ParseMode validates a recall/export scope_mode string. Empty defaults to ModeAncestors.
func ParseMode(raw string) (Mode, error) {
	trimmed := strings.ToLower(strings.TrimSpace(raw))
	if trimmed == "" {
		return ModeAncestors, nil
	}
	switch Mode(trimmed) {
	case ModeAncestors, ModeExact, ModeSubtree, ModeLineage, ModeAll:
		return Mode(trimmed), nil
	default:
		return "", fmt.Errorf("%w: %q (expected ancestors, exact, subtree, lineage, or all)", ErrInvalidScopeMode, raw)
	}
}

// Ancestors returns every inherited scope from vault-global ("") through canonical inclusive.
// Example: "platform/payments/webhooks" -> ["", "platform", "platform/payments", "platform/payments/webhooks"].
func Ancestors(canonical string) []string {
	if canonical == "" {
		return []string{""}
	}
	parts := strings.Split(canonical, "/")
	out := make([]string, 0, len(parts)+1)
	out = append(out, "")
	for i := range parts {
		out = append(out, strings.Join(parts[:i+1], "/"))
	}
	return out
}

// Depth returns the segment count ("" -> 0, "platform" -> 1, "platform/payments" -> 2).
func Depth(canonical string) int {
	if canonical == "" {
		return 0
	}
	return strings.Count(canonical, "/") + 1
}

// IsAncestor reports whether ancestor is a strict ancestor of descendant.
// Vault-global ("") is an ancestor of every non-empty scope.
func IsAncestor(ancestor, descendant string) bool {
	if descendant == "" || ancestor == descendant {
		return false
	}
	if ancestor == "" {
		return true
	}
	return strings.HasPrefix(descendant, ancestor+"/")
}

// IsDescendant reports whether descendant lies strictly beneath ancestor.
func IsDescendant(descendant, ancestor string) bool {
	return IsAncestor(ancestor, descendant)
}

// SubtreeBounds returns byte-order [lower, upper) bounds matching all strict descendants
// of canonical under ASCII/BINARY/"C" collation ('/' is 0x2F, '0' is 0x30).
func SubtreeBounds(canonical string) (lower, upper string) {
	return canonical + "/", canonical + "0"
}

// Matches evaluates whether candidateScope satisfies (targetScope, mode).
func Matches(candidateScope, targetScope string, mode Mode) bool {
	if mode == "" {
		mode = ModeAncestors
	}
	if mode == ModeAll {
		return true
	}
	if targetScope == "" {
		switch mode {
		case ModeExact, ModeAncestors:
			return candidateScope == ""
		default:
			return true
		}
	}

	switch mode {
	case ModeExact:
		return candidateScope == targetScope
	case ModeAncestors:
		return candidateScope == "" || candidateScope == targetScope || IsAncestor(candidateScope, targetScope)
	case ModeSubtree:
		return candidateScope == targetScope || IsDescendant(candidateScope, targetScope)
	case ModeLineage:
		return candidateScope == "" || candidateScope == targetScope || IsAncestor(candidateScope, targetScope) || IsDescendant(candidateScope, targetScope)
	default:
		return false
	}
}

// Affinity computes specificity relevance in [0.10, 1.00] for RerankResults:
//   - active == ""                    -> 0.50 (neutral)
//   - candidate == active             -> 1.00 (exact)
//   - candidate == ""                 -> 0.55 (vault-global floor)
//   - strict ancestor (distance d>=1) -> max(0.45, 0.85 - 0.12*(d-1))
//   - strict descendant               -> 0.65
//   - unrelated sibling               -> 0.10
func Affinity(candidateScope, activeScope string) float32 {
	if activeScope == "" {
		return 0.50
	}
	if candidateScope == activeScope {
		return 1.00
	}
	if candidateScope == "" {
		return 0.55
	}
	if IsAncestor(candidateScope, activeScope) {
		dist := Depth(activeScope) - Depth(candidateScope)
		score := float32(0.85) - 0.12*float32(dist-1)
		if score < 0.45 {
			score = 0.45
		}
		return score
	}
	if IsDescendant(candidateScope, activeScope) {
		return 0.65
	}
	return 0.10
}

// Join combines an optional prefix scope and child scope and validates the result.
func Join(prefix, child string) (string, error) {
	p, err := Normalize(prefix)
	if err != nil {
		return "", err
	}
	c, err := Normalize(child)
	if err != nil {
		return "", err
	}
	if p == "" {
		return c, nil
	}
	if c == "" {
		return p, nil
	}
	return Normalize(p + "/" + c)
}

var dirSanitizeRe = regexp.MustCompile(`[^a-z0-9._-]+`)

// FromRelativeDir deterministically derives a valid canonical scope from a relative directory
// path (e.g., for Obsidian vault folders or monorepo subdirectories) joined with basePrefix.
func FromRelativeDir(basePrefix, relDir string) (string, error) {
	base, err := Normalize(basePrefix)
	if err != nil {
		return "", err
	}
	clean := path.Clean(strings.ReplaceAll(strings.TrimSpace(relDir), "\\", "/"))
	if clean == "." || clean == "" || clean == "/" {
		return base, nil
	}
	if strings.HasPrefix(clean, "..") || strings.HasPrefix(clean, "/") {
		return "", fmt.Errorf("%w: relative directory %q escapes root", ErrInvalidScope, relDir)
	}

	rawParts := strings.Split(clean, "/")
	var cleanParts []string
	if base != "" {
		cleanParts = append(cleanParts, strings.Split(base, "/")...)
	}
	for _, seg := range rawParts {
		if seg == "" || seg == "." {
			continue
		}
		s := strings.ToLower(seg)
		s = dirSanitizeRe.ReplaceAllString(s, "-")
		s = strings.TrimLeft(s, ".-_")
		s = strings.TrimRight(s, "-")
		if s == "" {
			continue
		}
		if len(s) > MaxSegmentLength {
			s = s[:MaxSegmentLength]
		}
		if len(cleanParts) >= MaxDepth {
			break
		}
		cleanParts = append(cleanParts, s)
	}
	if len(cleanParts) == 0 {
		return "", nil
	}
	// Truncate trailing segments if joined string would exceed MaxLength
	for len(cleanParts) > 0 && len(strings.Join(cleanParts, "/")) > MaxLength {
		cleanParts = cleanParts[:len(cleanParts)-1]
	}
	return Normalize(strings.Join(cleanParts, "/"))
}
