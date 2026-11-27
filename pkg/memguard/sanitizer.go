package memguard

import (
	"regexp"
	"strings"

	"golang.org/x/text/unicode/norm"
)

const maxSanitizePasses = 8

// Precompiled package-level regexes for thread-safe sanitization (zero -race races).
var (
	wsURLRe = regexp.MustCompile(`(?i)\bwss?://[^\s"'<>]+`)

	localhostTargetRe = regexp.MustCompile(`(?i)\b(?:https?|wss?|ftp|tcp|grpc)://(?:localhost|127(?:\.\d{1,3}){3}|0\.0\.0\.0|\[::1\]|169\.254\.169\.254)(?::\d{1,5})?(?:/[^\s"'<>]*)?`)

	artificialDelimiterRe = regexp.MustCompile(
		`(?i)(?:</?(?:untrusted_artifact|untrusted_code_artifact|untrusted_external_artifact|untrusted_[a-z0-9_-]+|tool_call|tool_response|tool_results|function_call|call_tool|openclaw_execute|control_panel|system_override|root_exec|admin_[a-z0-9_-]+|system_[a-z0-9_-]+|system|instruction|developer)(?:\s+[^>]*)?>|<\|im_start\|>|<\|im_end\|>|<\|system\|>|<\|user\|>|<\|assistant\|>|\[/?INST\]|<<\/?SYS>>)`,
	)

	fenceTagRe = regexp.MustCompile(`(?i)</?untrusted_artifact(?:\s+[^>]*)?>`)
)

// SanitizerResult details the outcome of pre-flight context sanitization.
type SanitizerResult struct {
	Original              string   `json:"original"`
	Cleaned               string   `json:"cleaned"`
	WebSocketNeutralized  int      `json:"websocket_neutralized"`
	LocalhostNeutralized  int      `json:"localhost_neutralized"`
	DelimitersNeutralized int      `json:"delimiters_neutralized"`
	TotalNeutralized      int      `json:"total_neutralized"`
	NeutralizedItems      []string `json:"neutralized_items,omitempty"`
}

// PreFlightSanitizer detects and neutralizes embedded WebSockets, localhost/loopback
// pivot targets, and artificial prompt injection delimiters using iterative passes
// plus a post-sanitize verification re-scan.
type PreFlightSanitizer struct{}

// NewPreFlightSanitizer initializes a stateless, concurrency-safe PreFlightSanitizer.
func NewPreFlightSanitizer() *PreFlightSanitizer {
	return &PreFlightSanitizer{}
}

// Sanitize scans and neutralizes dangerous patterns in the input text.
func (s *PreFlightSanitizer) Sanitize(input string) *SanitizerResult {
	res := &SanitizerResult{
		Original: input,
	}

	// Normalize NFKC and strip invisible/format runes first so hidden runes cannot split tags.
	cleaned, _, _ := StripInvisibleUnicode(norm.NFKC.String(input))

	// Iterative neutralization passes defeat nested delimiter reassembly
	// (e.g., `<<tool_call>tool_call>` or `</untrusted_</untrusted_artifact>artifact>`).
	for pass := 0; pass < maxSanitizePasses; pass++ {
		before := cleaned

		if wsURLRe.MatchString(cleaned) {
			cleaned = wsURLRe.ReplaceAllStringFunc(cleaned, func(m string) string {
				res.WebSocketNeutralized++
				res.NeutralizedItems = append(res.NeutralizedItems, "websocket:"+m)
				return "[NEUTRALIZED_WEBSOCKET]"
			})
		}

		if localhostTargetRe.MatchString(cleaned) {
			cleaned = localhostTargetRe.ReplaceAllStringFunc(cleaned, func(m string) string {
				res.LocalhostNeutralized++
				res.NeutralizedItems = append(res.NeutralizedItems, "localhost:"+m)
				return "[NEUTRALIZED_LOCALHOST]"
			})
		}

		if artificialDelimiterRe.MatchString(cleaned) {
			cleaned = artificialDelimiterRe.ReplaceAllStringFunc(cleaned, func(m string) string {
				res.DelimitersNeutralized++
				res.NeutralizedItems = append(res.NeutralizedItems, "delimiter:"+m)
				return " "
			})
		}

		if cleaned == before {
			break
		}
	}

	// Post-sanitize verification re-scan: guarantee no residual fence or artificial delimiter survives.
	if artificialDelimiterRe.MatchString(cleaned) || fenceTagRe.MatchString(cleaned) {
		cleaned = artificialDelimiterRe.ReplaceAllString(cleaned, " ")
		cleaned = fenceTagRe.ReplaceAllString(cleaned, " ")
		res.DelimitersNeutralized++
		res.NeutralizedItems = append(res.NeutralizedItems, "delimiter:post_rescan_cleanup")
	}

	res.TotalNeutralized = res.WebSocketNeutralized + res.LocalhostNeutralized + res.DelimitersNeutralized
	res.Cleaned = cleaned
	return res
}

// Neutralize returns the sanitized string directly.
func (s *PreFlightSanitizer) Neutralize(input string) string {
	return s.Sanitize(input).Cleaned
}

// FenceUntrustedArtifact wraps untrusted content inside strict <untrusted_artifact>
// boundary fences after stripping invisible runes and iteratively neutralizing nested
// delimiter tags.
func (s *PreFlightSanitizer) FenceUntrustedArtifact(input string) string {
	sanitized := s.Neutralize(input)
	// Defensive post-check ensuring zero <untrusted_artifact> tags exist inside body.
	for pass := 0; pass < maxSanitizePasses && fenceTagRe.MatchString(sanitized); pass++ {
		sanitized = fenceTagRe.ReplaceAllString(sanitized, " ")
	}
	return "<untrusted_artifact>\n" + strings.TrimSpace(sanitized) + "\n</untrusted_artifact>"
}

// FenceUntrustedArtifact is a package-level convenience helper wrapping untrusted content
// in strict <untrusted_artifact> boundary fences.
func FenceUntrustedArtifact(input string) string {
	return NewPreFlightSanitizer().FenceUntrustedArtifact(input)
}
