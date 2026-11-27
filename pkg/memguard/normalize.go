package memguard

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const (
	// MaxContentLength is the maximum permitted payload length (1 MB).
	MaxContentLength = 1024 * 1024
	// AgentIDPattern validates canonical agent identifiers.
	AgentIDPattern = `^[a-zA-Z0-9_\-\.]{1,64}$`
	// maxDecodeDepth bounds nested Base64/Hex decoding iterations to prevent DoS.
	maxDecodeDepth = 3
)

var (
	ErrInvalidAgentID  = errors.New("invalid agent_id format: must be 1-64 alphanumeric, dash, dot, or underscore chars")
	ErrContentEmpty    = errors.New("content cannot be empty")
	ErrContentTooLarge = errors.New("content exceeds maximum allowed size (1MB)")
	ErrInvalidTaint    = errors.New("taint field missing or invalid")
)

// Precompiled package-level regexes (immutable, safe for concurrent use under -race).
var (
	agentIDRe      = regexp.MustCompile(AgentIDPattern)
	htmlCommentRe  = regexp.MustCompile(`(?s)<!--(.*?)-->`)
	mdCommentRe    = regexp.MustCompile(`(?m)^\[//\]:\s*#\s*\((.+?)\)\s*$`)
	roleMarkerRe   = regexp.MustCompile(`(?i)(<\|im_start\|>|<\|im_end\|>|<\|system\|>|<\|user\|>|<\|assistant\|>|\[/?INST\]|<<\/?SYS>>|^\s*###\s*(?:system|instruction|developer)\s*:)`)
	base64TokenRe  = regexp.MustCompile(`(?:^|[^A-Za-z0-9+/=_-])([A-Za-z0-9+/_-]{16,}={0,2})(?:$|[^A-Za-z0-9+/=_-])`)
	hexPrefixedRe  = regexp.MustCompile(`(?i)\b0x([0-9a-f]{16,})\b`)
	hexEscapeSeqRe = regexp.MustCompile(`(?i)(?:\\x[0-9a-f]{2}){8,}`)
	hexStandaloneRe = regexp.MustCompile(`(?i)(?:^|[^0-9a-fA-F])([0-9a-fA-F]{24,})(?:$|[^0-9a-fA-F])`)
)

// MemoryRecord represents a strictly typed memory write or context exchange envelope.
type MemoryRecord struct {
	AgentID     string            `json:"agent_id"`
	TargetAgent string            `json:"target_agent,omitempty"`
	Taint       TaintLevel        `json:"taint"`
	Content     string            `json:"content"`
	TaskIntent  string            `json:"task_intent,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Signature   string            `json:"signature,omitempty"`
	Timestamp   string            `json:"timestamp,omitempty"`
}

// Validate verifies that the MemoryRecord satisfies strict structural schema constraints.
func (r *MemoryRecord) Validate() error {
	if r == nil {
		return ErrContentEmpty
	}
	if !agentIDRe.MatchString(r.AgentID) {
		return ErrInvalidAgentID
	}
	if strings.TrimSpace(r.Content) == "" {
		return ErrContentEmpty
	}
	if len(r.Content) > MaxContentLength {
		return ErrContentTooLarge
	}
	if !r.Taint.IsValid() {
		return ErrInvalidTaint
	}
	return nil
}

// ComputeSignature computes a length-prefixed HMAC-SHA256 over the provenance-critical fields.
func (r *MemoryRecord) ComputeSignature(secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	writeLP := func(s string) {
		fmt.Fprintf(mac, "%d:%s|", len(s), s)
	}
	writeLP(r.AgentID)
	writeLP(r.TargetAgent)
	writeLP(string(r.Taint))
	writeLP(r.TaskIntent)
	writeLP(r.Content)
	writeLP(r.Timestamp)
	return hex.EncodeToString(mac.Sum(nil))
}

// Sign populates r.Signature using the provided HMAC secret.
func (r *MemoryRecord) Sign(secret []byte) {
	r.Signature = r.ComputeSignature(secret)
}

// VerifySignature checks r.Signature in constant time against the provided HMAC secret.
func (r *MemoryRecord) VerifySignature(secret []byte) bool {
	if r.Signature == "" {
		return false
	}
	expected := r.ComputeSignature(secret)
	return hmac.Equal([]byte(r.Signature), []byte(expected))
}

// NormalizationResult holds the cleaned text along with cloaking and marker security telemetry.
type NormalizationResult struct {
	Original         string   `json:"original"`
	Cleaned          string   `json:"cleaned"`
	StrippedRunes    int      `json:"stripped_runes_count"`
	MarkersFound     []string `json:"markers_found"`
	DecodedPayloads  []string `json:"decoded_payloads"`
	UnwrappedContent []string `json:"unwrapped_content"`
}

// Normalize cleans and normalizes content using NFKC normalization, stripping invisible
// Unicode/Format/Variation Selector/Plane-14 Tag runes, unwrapping hidden comments,
// and recursively decoding nested Base64/Hex cloaked payloads.
func Normalize(input string) *NormalizationResult {
	res := &NormalizationResult{
		Original: input,
	}

	// 1. Strip invisible Unicode & recover Plane-14 Tag ASCII payloads (U+E0000-U+E007F)
	stripped, strippedCount, tagPayloads := StripInvisibleUnicode(input)
	res.StrippedRunes = strippedCount

	// 2. Apply NFKC normalization to collapse homoglyphs / fullwidth characters
	nfkcText := norm.NFKC.String(stripped)

	// Re-strip any format/zero-width runes exposed after NFKC decomposition
	nfkcClean, postStripCount, postTagPayloads := StripInvisibleUnicode(nfkcText)
	res.StrippedRunes += postStripCount

	// 3. Unwrap HTML/Markdown comments and detect LLM instruction markers
	unwrappedComments := extractComments(nfkcClean)
	res.UnwrappedContent = append(res.UnwrappedContent, unwrappedComments...)

	flattened, markers := FlattenInstructionMarkers(nfkcClean)
	res.MarkersFound = markers
	res.Cleaned = flattened

	// 4. Collect recovered tag payloads + recursively extract Base64/Hex cloaked payloads
	seen := make(map[string]struct{})
	addDecoded := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		res.DecodedPayloads = append(res.DecodedPayloads, p)
	}

	for _, tp := range tagPayloads {
		addDecoded(tp)
		for _, nested := range ExtractAndDecodePayloads(tp) {
			addDecoded(nested)
		}
	}
	for _, tp := range postTagPayloads {
		addDecoded(tp)
	}

	// Scan both pre-flattened text (including inside HTML comments) and unwrapped comments
	for _, decoded := range ExtractAndDecodePayloads(nfkcClean) {
		addDecoded(decoded)
	}
	for _, comment := range unwrappedComments {
		for _, decoded := range ExtractAndDecodePayloads(comment) {
			addDecoded(decoded)
		}
	}

	return res
}

// SanitizeText returns the normalized clean text with cloaking and markers neutralized.
func SanitizeText(input string) string {
	return Normalize(input).Cleaned
}

// isInvisibleOrFormatRune returns true for zero-width, Format (Cf), Variation Selector,
// directional override/isolate, and Plane-14 Tag runes.
func isInvisibleOrFormatRune(r rune) bool {
	if r >= 0xE0000 && r <= 0xE007F {
		return true
	}
	if (r >= 0x200B && r <= 0x200F) || r == 0xFEFF || r == 0x00AD {
		return true
	}
	if (r >= 0x202A && r <= 0x202E) || (r >= 0x2060 && r <= 0x206F) {
		return true
	}
	if (r >= 0xFE00 && r <= 0xFE0F) || (r >= 0xE0100 && r <= 0xE01EF) {
		return true
	}
	if unicode.Is(unicode.Cf, r) {
		return true
	}
	return false
}

// StripInvisibleUnicode removes zero-width, Format (Cf), Variation Selector, directional
// override, and Plane-14 Tag runes, while recovering ASCII text smuggled inside Plane-14
// Unicode Tag sequences (U+E0000 to U+E007F).
func StripInvisibleUnicode(input string) (string, int, []string) {
	var clean strings.Builder
	clean.Grow(len(input))

	var currentTag strings.Builder
	var recovered []string
	stripped := 0

	flushTag := func() {
		if currentTag.Len() > 0 {
			s := strings.TrimSpace(currentTag.String())
			if len(s) >= 4 {
				recovered = append(recovered, s)
			}
			currentTag.Reset()
		}
	}

	for _, r := range input {
		if r >= 0xE0000 && r <= 0xE007F {
			stripped++
			ascii := r - 0xE0000
			if ascii == '\t' || ascii == '\n' || ascii == '\r' || (ascii >= 0x20 && ascii <= 0x7E) {
				currentTag.WriteRune(ascii)
			}
			continue
		}
		flushTag()
		if isInvisibleOrFormatRune(r) {
			stripped++
			continue
		}
		clean.WriteRune(r)
	}
	flushTag()

	return clean.String(), stripped, recovered
}

func extractComments(input string) []string {
	var out []string
	for _, m := range htmlCommentRe.FindAllStringSubmatch(input, -1) {
		if len(m) > 1 {
			if body := strings.TrimSpace(m[1]); body != "" {
				out = append(out, body)
			}
		}
	}
	for _, m := range mdCommentRe.FindAllStringSubmatch(input, -1) {
		if len(m) > 1 {
			if body := strings.TrimSpace(m[1]); body != "" {
				out = append(out, body)
			}
		}
	}
	return out
}

// FlattenInstructionMarkers strips HTML/Markdown comment wrappers and flags LLM role markers.
func FlattenInstructionMarkers(input string) (string, []string) {
	var markers []string
	seen := make(map[string]struct{})
	addMarker := func(m string) {
		if _, ok := seen[m]; !ok {
			seen[m] = struct{}{}
			markers = append(markers, m)
		}
	}

	out := input
	if htmlCommentRe.MatchString(out) {
		addMarker("html_comment")
		out = htmlCommentRe.ReplaceAllString(out, " $1 ")
	}
	if mdCommentRe.MatchString(out) {
		addMarker("markdown_comment")
		out = mdCommentRe.ReplaceAllString(out, " $1 ")
	}

	for _, match := range roleMarkerRe.FindAllString(out, -1) {
		addMarker("role_marker:" + strings.TrimSpace(match))
	}

	return out, markers
}

// ExtractAndDecodePayloads discovers Base64 and Hex encoded payloads (including nested layers
// up to maxDecodeDepth) and returns those that decode to readable text instructions.
func ExtractAndDecodePayloads(input string) []string {
	var results []string
	seen := make(map[string]struct{})
	queue := []struct {
		text  string
		depth int
	}{{text: input, depth: 0}}

	queued := make(map[string]struct{})
	enqueue := func(text string, nextDepth int) {
		if nextDepth >= maxDecodeDepth {
			return
		}
		if _, ok := queued[text]; ok {
			return
		}
		queued[text] = struct{}{}
		queue = append(queue, struct {
			text  string
			depth int
		}{text: text, depth: nextDepth})
	}

	addResult := func(decoded string, depth int) {
		cleaned, _, tagPayloads := StripInvisibleUnicode(norm.NFKC.String(decoded))
		cleaned = strings.TrimSpace(cleaned)
		if cleaned != "" {
			if isReadableDecodedText(cleaned) {
				if _, ok := seen[cleaned]; !ok {
					seen[cleaned] = struct{}{}
					results = append(results, cleaned)
				}
				enqueue(cleaned, depth+1)
			} else if isPotentialNestedEncoding(cleaned) {
				// Intermediate Base64/Hex layer (e.g., Base64-of-Base64): peel further
				// without emitting non-text noise unless an inner layer decodes cleanly.
				enqueue(cleaned, depth+1)
			}
		}
		for _, tp := range tagPayloads {
			if _, ok := seen[tp]; !ok {
				seen[tp] = struct{}{}
				results = append(results, tp)
			}
			enqueue(tp, depth+1)
		}
	}

	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]
		if curr.depth >= maxDecodeDepth {
			continue
		}

		// 1. Base64 candidates
		for _, m := range base64TokenRe.FindAllStringSubmatch(curr.text, -1) {
			if len(m) < 2 {
				continue
			}
			tok := m[1]
			if !looksLikeBase64Payload(tok) {
				continue
			}
			if dec, ok := tryDecodeBase64(tok); ok && (isReadableDecodedText(dec) || isPotentialNestedEncoding(dec)) {
				addResult(dec, curr.depth)
			}
		}

		// 2. \xHH escaped hex sequences
		for _, seq := range hexEscapeSeqRe.FindAllString(curr.text, -1) {
			stripped := strings.ReplaceAll(strings.ToLower(seq), `\x`, "")
			if raw, err := hex.DecodeString(stripped); err == nil && (isReadableDecodedText(string(raw)) || isPotentialNestedEncoding(string(raw))) {
				addResult(string(raw), curr.depth)
			}
		}

		// 3. 0x-prefixed hex payloads
		for _, m := range hexPrefixedRe.FindAllStringSubmatch(curr.text, -1) {
			if len(m) < 2 || len(m[1])%2 != 0 {
				continue
			}
			if raw, err := hex.DecodeString(m[1]); err == nil && (isReadableDecodedText(string(raw)) || isPotentialNestedEncoding(string(raw))) {
				addResult(string(raw), curr.depth)
			}
		}

		// 4. Standalone long even-length hex payloads (>= 24 hex chars -> >= 12 decoded bytes)
		for _, m := range hexStandaloneRe.FindAllStringSubmatch(curr.text, -1) {
			if len(m) < 2 || len(m[1])%2 != 0 {
				continue
			}
			if raw, err := hex.DecodeString(m[1]); err == nil && (isReadableDecodedText(string(raw)) || isPotentialNestedEncoding(string(raw))) {
				addResult(string(raw), curr.depth)
			}
		}
	}

	return results
}

func isPotentialNestedEncoding(s string) bool {
	trimmed := strings.TrimSpace(s)
	if len(trimmed) < 16 || !utf8.ValidString(trimmed) {
		return false
	}
	for _, r := range trimmed {
		if r < 0x20 || r > 0x7E {
			return false
		}
	}
	return looksLikeBase64Payload(trimmed) || hexPrefixedRe.MatchString(trimmed) || hexStandaloneRe.MatchString(trimmed) || hexEscapeSeqRe.MatchString(trimmed)
}

func looksLikeBase64Payload(tok string) bool {
	if len(tok) < 16 {
		return false
	}
	// Reject pure hex strings here (handled by hex decoder) and snake_case/kebab-case identifiers
	if strings.Contains(tok, "_") && !strings.ContainsAny(tok, "+/=") {
		// Base64URL can use '_' and '-', but plain lowercase snake_case words like
		// "quarantined_observations" should not be treated as Base64.
		hasUpper := false
		hasDigit := false
		for _, r := range tok {
			if r >= 'A' && r <= 'Z' {
				hasUpper = true
			}
			if r >= '0' && r <= '9' {
				hasDigit = true
			}
		}
		if !hasUpper && !hasDigit {
			return false
		}
	}
	// Require either explicit padding/Base64 punctuation or mixed case/digits
	hasUpper, hasLower, hasDigit, hasB64Punct := false, false, false, false
	for _, r := range tok {
		switch {
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= '0' && r <= '9':
			hasDigit = true
		case r == '+' || r == '/' || r == '=':
			hasB64Punct = true
		}
	}
	if hasB64Punct {
		return true
	}
	return (hasUpper && hasLower) || (hasDigit && (hasUpper || hasLower))
}

func tryDecodeBase64(tok string) (string, bool) {
	encoders := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, enc := range encoders {
		b, err := enc.DecodeString(tok)
		if err == nil && len(b) >= 8 {
			return string(b), true
		}
	}
	return "", false
}

func isReadableDecodedText(s string) bool {
	if len(s) < 8 || !utf8.ValidString(s) {
		return false
	}
	printable := 0
	letters := 0
	spacesOrPunct := 0
	total := 0
	for _, r := range s {
		total++
		if r == '\n' || r == '\r' || r == '\t' || (r >= 0x20 && r <= 0x7E) {
			printable++
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				letters++
			}
			if r == ' ' || r == '\t' || r == '\n' || r == '<' || r == '>' || r == '/' || r == ':' || r == '-' || r == '{' || r == '"' {
				spacesOrPunct++
			}
		}
	}
	if total == 0 {
		return false
	}
	// At least 90% printable ASCII, contains meaningful alphabetic content and word/syntax structure
	return float64(printable)/float64(total) >= 0.90 && letters >= 5 && spacesOrPunct >= 1
}
