package capsule

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/bonjoski/coppermind/pkg/security"
)

const (
	// MaxDistillFileBytes enforces a strict 256KB anti-DoS cap on --from-file lesson markdown inputs.
	MaxDistillFileBytes = 256 * 1024
)

var (
	ErrDistillValidation      = errors.New("lesson distillation validation failed")
	ErrDistillFileTooLarge    = errors.New("lesson file exceeds maximum 256KB size limit")
	ErrDistillFirewallBlocked = errors.New("lesson distillation blocked by cognitive firewall")
	ErrDistillSecretDetected  = errors.New("lesson distillation blocked by secret quarantine")
	ErrDistillHTMLRejected    = errors.New("lesson distillation rejected unsafe HTML/XSS markup")
	ErrDistillInternalLeak    = errors.New("lesson distillation blocked internal hostname or private IP leakage")
	ErrDistillVerifyCmdBad    = errors.New("lesson distillation rejected unauthorized or unsafe verify_cmd")
)

// ValidAegisboxProbeCategories matches aegisbox/pkg/aisafety ProbeCategory values.
var validAegisboxProbeCategories = map[string]struct{}{
	"indirect_prompt_injection": {},
	"rag_cross_tenant_bleed":    {},
	"tool_arg_path_traversal":   {},
	"tool_arg_ssrf":             {},
	"mcp_scope_escalation":      {},
	"secret_egress_canary":      {},
}

// DistillInput captures structured lesson fields parsed from CLI flags or a sanitized lesson-to-capsule.md file.
type DistillInput struct {
	ID             string
	Domain         string
	Title          string
	Pattern        string
	Analogy        string
	Fix            string
	Why            string
	Triggers       []string
	ReqTriggers    []TriggerFlag
	Given          string
	When           string
	Then           string
	VerifyCmd      string
	KataRef        string
	CWEOrOWASP     string
	ProbeCategory  string
	ProbePayload   string
	ExpectedSignal string
	IncludeProbe   bool
}

// AegisboxProbeStub is a custom regression probe JSON compatible with
// `aegisbox test --ai-safety --probes-file <file>`.
type AegisboxProbeStub struct {
	ProbeID        string `json:"probe_id"`
	Category       string `json:"category"`
	Payload        string `json:"payload"`
	ExpectedSignal string `json:"expected_signal"`
	FixPatchHint   string `json:"fix_patch_hint"`
	WhyOneLiner    string `json:"why_one_liner"`
}

// DistillResult holds the validated Production-to-Ideation flywheel artifacts.
type DistillResult struct {
	MentorCard         MentorCard         `json:"mentor_card"`
	AbuseCaseCriterion AbuseCaseCriterion `json:"abuse_case_criterion"`
	AegisboxProbe      *AegisboxProbeStub `json:"aegisbox_probe,omitempty"`
}

// DistillWrittenFiles reports file paths emitted by WriteDistillArtifacts.
type DistillWrittenFiles struct {
	MentorCardPath string
	AbuseCasePath  string
	ProbeStubPath  string
}

var (
	// RFC1918 & link-local private IPv4 ranges (explicitly NOT blocking loopback 127.0.0.1).
	rfc1918TenRegex      = regexp.MustCompile(`\b10\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b`)
	rfc1918OneNineTwo    = regexp.MustCompile(`\b192\.168\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b`)
	rfc1918OneSevenTwo   = regexp.MustCompile(`\b172\.(?:1[6-9]|2\d|3[01])\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b`)
	linkLocalIPv4Regex   = regexp.MustCompile(`\b169\.254\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b`)
	internalDomainRegex  = regexp.MustCompile(`(?i)\b[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*\.(?:corp|internal|intranet|localdomain|svc\.cluster\.local|lan|home\.arpa)\b`)
	nonSlugRunesRegex    = regexp.MustCompile(`[^a-z0-9-]+`)
	multiDashRegex       = regexp.MustCompile(`-{2,}`)
	markdownLineNumRegex = regexp.MustCompile(`^\s*(?:[-*+]\s+|\d+\.\s+)?`)
)

// HasInternalHostOrPrivateIP checks whether text contains RFC1918/link-local IPs or private internal domains
// (.corp, .internal, .intranet, .localdomain, .svc.cluster.local, .lan, .home.arpa) that must never leak
// into reusable open-source capsules. Returns (matched, genericCategory) without echoing sensitive values.
func HasInternalHostOrPrivateIP(s string) (bool, string) {
	if s == "" {
		return false, ""
	}
	folded := foldHomoglyphs(s)
	for _, cand := range []string{s, folded} {
		if rfc1918TenRegex.MatchString(cand) {
			return true, "RFC1918 10.0.0.0/8 private IP"
		}
		if rfc1918OneNineTwo.MatchString(cand) {
			return true, "RFC1918 192.168.0.0/16 private IP"
		}
		if rfc1918OneSevenTwo.MatchString(cand) {
			return true, "RFC1918 172.16.0.0/12 private IP"
		}
		if linkLocalIPv4Regex.MatchString(cand) {
			return true, "RFC3927 169.254.0.0/16 link-local IP"
		}
		if internalDomainRegex.MatchString(cand) {
			return true, "private/internal domain (.corp/.internal)"
		}
	}
	return false, ""
}

func isDistillIdentifierField(fieldName string) bool {
	switch fieldName {
	case "id", "domain", "kata_ref", "cwe_or_owasp", "probe_category", "expected_signal":
		return true
	default:
		return false
	}
}

// InspectDistillField runs the complete fail-closed quarantine gate on a single distillation field:
// invisible/bidi/control/ANSI rejection, HTML/XSS rejection, OWASP LLM01 cognitive firewall (NFKC + homoglyphs),
// secret & high-entropy credential quarantine, and RFC1918/internal domain leak rejection.
// Error messages intentionally NEVER echo raw offending values so canary secrets cannot leak into logs.
func InspectDistillField(fieldName, value string, allowNewlines bool) error {
	if value == "" {
		return nil
	}

	if bad, r := hasInvisibleOrBidiRune(value); bad {
		return fmt.Errorf("%w: invisible/bidi Unicode rune U+%04X detected in %s", ErrDistillFirewallBlocked, r, fieldName)
	}
	if ansiEscapeRegex.MatchString(value) {
		return fmt.Errorf("%w: ANSI escape sequence detected in %s", ErrDistillValidation, fieldName)
	}
	for _, r := range value {
		if allowNewlines && (r == '\n' || r == '\r' || r == '\t') {
			continue
		}
		if (r < 0x20 && r != '\t') || r == 0x7f {
			return fmt.Errorf("%w: control character 0x%02X detected in %s", ErrDistillValidation, r, fieldName)
		}
	}

	if HasUnsafeHTMLOrXSS(value) {
		return fmt.Errorf("%w: unsafe HTML/XSS markup detected in %s", ErrDistillHTMLRejected, fieldName)
	}

	folded := foldHomoglyphs(value)
	for _, candidate := range []string{value, folded} {
		fw, err := security.InspectCognitiveThreats(candidate)
		if err != nil {
			return fmt.Errorf("%w: cognitive threat inspection error on %s", ErrDistillFirewallBlocked, fieldName)
		}
		if fw.IsCritical || fw.TaintScore > 0 || len(fw.Flags) > 0 {
			return fmt.Errorf("%w: OWASP LLM01 injection pattern %v detected in %s", ErrDistillFirewallBlocked, fw.Flags, fieldName)
		}
		for _, pat := range mentorExtraHijackPatterns {
			if pat.Regex.MatchString(candidate) {
				return fmt.Errorf("%w: %s detected in %s", ErrDistillFirewallBlocked, pat.Name, fieldName)
			}
		}
	}

	// Internal IP / private domain leak guard (fail-closed) runs before generic high-entropy
	// heuristics so internal URLs like https://db.prod.acme.corp or http://192.168.x.x are
	// precisely diagnosed as ErrDistillInternalLeak without echoing sensitive hostnames.
	if leaked, kind := HasInternalHostOrPrivateIP(value); leaked {
		return fmt.Errorf("%w: %s detected in %s (replace internal hostnames and private IPs with generic placeholders)",
			ErrDistillInternalLeak, kind, fieldName)
	}

	// Secret & Shannon-entropy credential quarantine (never echoing raw secret bytes in errors).
	if isDistillIdentifierField(fieldName) && isCleanIdentifierSlug(value) {
		secRes, err := security.SanitizeMemory("identifier " + value)
		if err != nil {
			return fmt.Errorf("%w: credential pattern rejected in %s", ErrDistillSecretDetected, fieldName)
		}
		for _, dt := range secRes.DetectedTypes {
			if dt != "High-Entropy Secret" {
				return fmt.Errorf("%w: secret pattern %v detected in %s", ErrDistillSecretDetected, secRes.DetectedTypes, fieldName)
			}
		}
	} else {
		secRes, err := security.SanitizeMemory(value)
		if err != nil {
			return fmt.Errorf("%w: raw credential or private key rejected in %s", ErrDistillSecretDetected, fieldName)
		}
		if secRes.RedactedCount > 0 {
			return fmt.Errorf("%w: secret pattern %v detected in %s", ErrDistillSecretDetected, secRes.DetectedTypes, fieldName)
		}
	}

	return nil
}

func isCleanIdentifierSlug(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// ParseLessonMarkdown reads a sanitized lesson-to-capsule.md stream bounded strictly to 256KB,
// quarantines the entire raw document fail-closed before extraction, and parses structured lesson fields.
func ParseLessonMarkdown(r io.Reader) (DistillInput, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxDistillFileBytes+1))
	if err != nil {
		return DistillInput{}, fmt.Errorf("%w: failed reading lesson markdown: %v", ErrDistillValidation, err)
	}
	if len(data) > MaxDistillFileBytes {
		return DistillInput{}, fmt.Errorf("%w: input exceeds %d bytes", ErrDistillFileTooLarge, MaxDistillFileBytes)
	}

	raw := string(data)
	// Fail-closed quarantine over the ENTIRE raw markdown document first so hidden secrets,
	// XSS tags, prompt injections, or internal hostnames anywhere in the file cannot slip through.
	if err := InspectDistillField("lesson_markdown", raw, true); err != nil {
		return DistillInput{}, err
	}

	in := DistillInput{IncludeProbe: true}
	lines := strings.Split(raw, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, ">") {
			continue
		}

		// Handle bulleted Given / When / Then lines (e.g. "- **Given** a caller with ...")
		if val, ok := extractMarkdownGWT(trimmed, "given"); ok {
			if in.Given == "" {
				in.Given = val
			}
			continue
		}
		if val, ok := extractMarkdownGWT(trimmed, "when"); ok {
			if in.When == "" {
				in.When = val
			}
			continue
		}
		if val, ok := extractMarkdownGWT(trimmed, "then"); ok {
			if in.Then == "" {
				in.Then = val
			}
			continue
		}

		label, val, ok := splitMarkdownKV(trimmed)
		if !ok || val == "" {
			continue
		}
		normLabel := normalizeLabel(label)
		switch {
		case normLabel == "id" || strings.Contains(normLabel, "mentorcard id") || strings.Contains(normLabel, "incident class"):
			if in.ID == "" || strings.Contains(normLabel, "mentorcard id") {
				in.ID = cleanMarkdownValue(val)
			}
		case normLabel == "domain" || strings.Contains(normLabel, "affected boundary"):
			in.Domain = mapBoundaryToDomain(cleanMarkdownValue(val))
		case normLabel == "title" || normLabel == "plain title":
			in.Title = cleanMarkdownValue(val)
		case normLabel == "pattern" || strings.Contains(normLabel, "what broke"):
			in.Pattern = cleanMarkdownValue(val)
		case normLabel == "analogy" || strings.Contains(normLabel, "deterministic analogy") || strings.Contains(normLabel, "engineering analogy"):
			in.Analogy = cleanMarkdownValue(val)
		case normLabel == "fix" || normLabel == "secure default" || strings.Contains(normLabel, "fix-forward") || strings.Contains(normLabel, "fix pattern"):
			in.Fix = cleanMarkdownValue(val)
		case normLabel == "why" || normLabel == "why one liner" || strings.Contains(normLabel, "business impact"):
			in.Why = cleanMarkdownValue(val)
		case normLabel == "triggers" || normLabel == "keywords" || normLabel == "tags":
			in.Triggers = append(in.Triggers, splitCSVOrList(cleanMarkdownValue(val))...)
		case normLabel == "verify cmd" || normLabel == "verify command" || normLabel == "verify":
			in.VerifyCmd = cleanMarkdownValue(val)
		case normLabel == "kata" || normLabel == "kata ref":
			in.KataRef = cleanMarkdownValue(val)
		case normLabel == "cwe" || normLabel == "cwe or owasp" || normLabel == "owasp":
			in.CWEOrOWASP = cleanMarkdownValue(val)
		case strings.Contains(normLabel, "probe category"):
			in.ProbeCategory = cleanMarkdownValue(val)
		case strings.Contains(normLabel, "reproducer payload") || normLabel == "payload" || normLabel == "probe payload":
			in.ProbePayload = cleanMarkdownValue(val)
		case strings.Contains(normLabel, "expected signal"):
			in.ExpectedSignal = cleanMarkdownValue(val)
		}
	}

	return in, nil
}

// ParseLessonMarkdownFile opens and parses a local sanitized lesson-to-capsule.md file (bounded 256KB).
func ParseLessonMarkdownFile(path string) (DistillInput, error) {
	if err := checkNoSymlinkPath(path); err != nil {
		return DistillInput{}, err
	}
	f, err := os.Open(path)
	if err != nil {
		return DistillInput{}, fmt.Errorf("failed opening lesson file %q: %w", path, err)
	}
	defer f.Close()
	return ParseLessonMarkdown(f)
}

func extractMarkdownGWT(line, kw string) (string, bool) {
	s := markdownLineNumRegex.ReplaceAllString(line, "")
	lower := strings.ToLower(s)
	boldPrefix := "**" + kw + "**"
	boldColonPrefix := "**" + kw + ":**"
	plainColonPrefix := kw + ":"
	var rest string
	switch {
	case strings.HasPrefix(lower, boldColonPrefix):
		rest = strings.TrimSpace(s[len(boldColonPrefix):])
	case strings.HasPrefix(lower, boldPrefix):
		rest = strings.TrimSpace(s[len(boldPrefix):])
		rest = strings.TrimPrefix(rest, ":")
		rest = strings.TrimSpace(rest)
	case strings.HasPrefix(lower, plainColonPrefix):
		rest = strings.TrimSpace(s[len(plainColonPrefix):])
	default:
		return "", false
	}
	if rest == "" {
		return "", false
	}
	return cleanMarkdownValue(rest), true
}

func splitMarkdownKV(line string) (string, string, bool) {
	s := markdownLineNumRegex.ReplaceAllString(line, "")
	// Handle "**Label:** value" or "**Label**: value"
	if strings.HasPrefix(s, "**") {
		end := strings.Index(s[2:], "**")
		if end > 0 {
			label := s[2 : 2+end]
			after := strings.TrimSpace(s[2+end+2:])
			if strings.HasSuffix(strings.TrimSpace(label), ":") {
				label = strings.TrimSuffix(strings.TrimSpace(label), ":")
				return label, after, true
			}
			if strings.HasPrefix(after, ":") {
				return label, strings.TrimSpace(strings.TrimPrefix(after, ":")), true
			}
		}
	}
	// Fallback plain "Label: value"
	idx := strings.Index(s, ":")
	if idx <= 0 || idx > 64 {
		return "", "", false
	}
	return strings.TrimSpace(s[:idx]), strings.TrimSpace(s[idx+1:]), true
}

func normalizeLabel(label string) string {
	cleaned := strings.ReplaceAll(label, "`", "")
	cleaned = strings.ReplaceAll(cleaned, "_", " ")
	cleaned = strings.ToLower(strings.TrimSpace(cleaned))
	// Strip parenthetical explanations like "(1 generic sentence, zero proprietary info)"
	if idx := strings.Index(cleaned, "("); idx >= 0 {
		cleaned = strings.TrimSpace(cleaned[:idx])
	}
	return strings.Join(strings.Fields(cleaned), " ")
}

func cleanMarkdownValue(val string) string {
	s := strings.TrimSpace(val)
	if len(s) >= 2 && s[0] == '`' && s[len(s)-1] == '`' {
		s = strings.TrimSpace(s[1 : len(s)-1])
	}
	// Unwrap single outer quotes only when not a JSON object/array
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = strings.TrimSpace(s[1 : len(s)-1])
	}
	// Strip inline backticks only from plain prose (not JSON payloads)
	if !strings.HasPrefix(s, "{") && !strings.HasPrefix(s, "[") {
		s = strings.ReplaceAll(s, "`", "")
	}
	return strings.TrimSpace(s)
}

func splitCSVOrList(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func mapBoundaryToDomain(raw string) string {
	l := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case l == "ai-app-rag" || l == "mcp-tools" || l == "secrets" || l == "deterministic-web":
		return l
	case strings.Contains(l, "mcp") || strings.Contains(l, "conjoiner") || strings.Contains(l, "tool"):
		return "mcp-tools"
	case strings.Contains(l, "secret") || strings.Contains(l, "locksmith") || strings.Contains(l, "pii") || strings.Contains(l, "key"):
		return "secrets"
	case strings.Contains(l, "rag") || strings.Contains(l, "prompt") || strings.Contains(l, "stormcage") || strings.Contains(l, "llm") || strings.Contains(l, "ai"):
		return "ai-app-rag"
	case strings.Contains(l, "web") || strings.Contains(l, "sql") || strings.Contains(l, "auth") || strings.Contains(l, "argus") || strings.Contains(l, "soulcaster"):
		return "deterministic-web"
	default:
		if l == "" {
			return "ai-app-rag"
		}
		return slugify(l)
	}
}

func slugify(s string) string {
	lower := strings.ToLower(strings.TrimSpace(s))
	lower = strings.ReplaceAll(lower, "_", "-")
	lower = nonSlugRunesRegex.ReplaceAllString(lower, "-")
	lower = multiDashRegex.ReplaceAllString(lower, "-")
	lower = strings.Trim(lower, "-")
	if len(lower) > 64 {
		lower = strings.Trim(lower[:64], "-")
	}
	return lower
}

func capRunes(s string, max int) string {
	trimmed := strings.TrimSpace(s)
	if utf8.RuneCountInString(trimmed) <= max {
		return trimmed
	}
	if max <= 3 {
		return string([]rune(trimmed)[:max])
	}
	runes := []rune(trimmed)[:max-3]
	cut := strings.TrimSpace(string(runes))
	if idx := strings.LastIndex(cut, " "); idx > len(cut)/2 {
		cut = strings.TrimSpace(cut[:idx])
	}
	return strings.TrimRight(cut, ",;:") + "..."
}

func inferTriggerFlags(domain string, rawTriggers []string, explicit []TriggerFlag) []TriggerFlag {
	seen := make(map[TriggerFlag]struct{})
	out := make([]TriggerFlag, 0, 3)
	add := func(f TriggerFlag) {
		if !ValidTriggerFlag(f) {
			return
		}
		if _, dup := seen[f]; dup {
			return
		}
		seen[f] = struct{}{}
		out = append(out, f)
	}
	for _, f := range explicit {
		add(f)
	}
	for _, raw := range rawTriggers {
		f := TriggerFlag(strings.ToLower(strings.TrimSpace(raw)))
		if ValidTriggerFlag(f) {
			add(f)
		}
	}
	if len(out) == 0 {
		switch strings.ToLower(domain) {
		case "mcp-tools":
			add(TriggerAIStateMutate)
		case "secrets":
			add(TriggerSecretsPII)
		case "deterministic-web":
			add(TriggerAuthDataMoney)
		case "supply-chain":
			add(TriggerSupplyChainMCP)
		default:
			add(TriggerAIRAGContext)
		}
	}
	return out
}

func inferProbeCategory(domain, explicit string, triggers []string, flags []TriggerFlag) string {
	if exp := strings.ToLower(strings.TrimSpace(explicit)); exp != "" {
		if _, ok := validAegisboxProbeCategories[exp]; ok {
			return exp
		}
	}
	joined := strings.ToLower(domain + " " + strings.Join(triggers, " "))
	switch {
	case strings.Contains(joined, "ssrf") || strings.Contains(joined, "egress") && strings.Contains(joined, "url"):
		return "tool_arg_ssrf"
	case strings.Contains(joined, "path") || strings.Contains(joined, "traversal") || strings.Contains(joined, "symlink"):
		return "tool_arg_path_traversal"
	case strings.Contains(joined, "tenant") || strings.Contains(joined, "vector") || strings.Contains(joined, "pgvector"):
		return "rag_cross_tenant_bleed"
	case strings.Contains(joined, "secret") || strings.Contains(joined, "api_key") || strings.Contains(joined, "pii") || strings.Contains(joined, "canary"):
		return "secret_egress_canary"
	case strings.Contains(joined, "mcp") || strings.Contains(joined, "refund") || strings.Contains(joined, "scope") || strings.Contains(joined, "tool"):
		return "mcp_scope_escalation"
	}
	for _, f := range flags {
		switch f {
		case TriggerAIStateMutate:
			return "mcp_scope_escalation"
		case TriggerSecretsPII:
			return "secret_egress_canary"
		case TriggerAIRAGContext:
			return "indirect_prompt_injection"
		}
	}
	return "indirect_prompt_injection"
}

func inferVerifyCmd(domain, probeCategory string, flags []TriggerFlag) string {
	for _, f := range flags {
		if f == TriggerSupplyChainMCP {
			return "argus vet --diff"
		}
	}
	switch strings.ToLower(domain) {
	case "secrets":
		return "aegisbox test --ai-safety --categories secret_egress_canary"
	case "deterministic-web":
		return "aegisbox test --authz"
	default:
		if probeCategory != "" {
			return "aegisbox test --ai-safety --categories " + probeCategory
		}
		return "aegisbox test --ai-safety"
	}
}

func extractKeywords(inputs ...string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, 12)
	add := func(tok string) {
		t := strings.ToLower(strings.TrimSpace(tok))
		if len(t) < 2 {
			return
		}
		if _, dup := seen[t]; dup {
			return
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	for _, in := range inputs {
		var cur strings.Builder
		flush := func() {
			if cur.Len() > 1 {
				w := cur.String()
				if len(w) >= 3 && !isDistillStopWord(w) {
					add(w)
				}
			}
			cur.Reset()
		}
		for _, r := range in {
			if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' {
				cur.WriteRune(unicode.ToLower(r))
			} else {
				flush()
			}
		}
		flush()
	}
	if len(out) > 12 {
		out = out[:12]
	}
	return out
}

func isDistillStopWord(w string) bool {
	switch w {
	case "the", "and", "for", "with", "that", "this", "from", "into", "when", "then", "given",
		"are", "was", "were", "can", "not", "all", "any", "before", "after", "only", "via", "must", "should":
		return true
	default:
		return false
	}
}

// DistillLesson executes the Production-to-Ideation flywheel (RFC-2026-11-22-48 Part C):
// 1. Runs EVERY input field through the fail-closed quarantine gate (cognitive firewall, HTML/XSS,
//    secret/entropy scanner, internal IP/domain detector).
// 2. Validates verify_cmd against the strict bonjoski verb allowlist.
// 3. Deterministically synthesizes a validated MentorCard, a validated AbuseCaseCriterion,
//    and an optional aegisbox custom probe stub JSON.
// 4. Cross-validates emitted artifacts against ValidateMentorManifest & ValidateRequirementsManifest.
func DistillLesson(in DistillInput) (*DistillResult, error) {
	// 1. Validate explicit verify_cmd against strict bonjoski allowlist first so rogue shell verbs
	//    or pipes (e.g. `curl ... | sh`, `; rm -rf /`) fail closed with ErrDistillVerifyCmdBad.
	if strings.TrimSpace(in.VerifyCmd) != "" {
		if err := ValidateVerifyCmd(in.VerifyCmd); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrDistillVerifyCmdBad, err)
		}
	}

	// 2. Fail-closed quarantine gate across EVERY supplied input field.
	fieldsToInspect := []struct {
		name          string
		val           string
		allowNewlines bool
	}{
		{"id", in.ID, false},
		{"domain", in.Domain, false},
		{"title", in.Title, false},
		{"pattern", in.Pattern, false},
		{"analogy", in.Analogy, false},
		{"fix", in.Fix, false},
		{"why", in.Why, false},
		{"given", in.Given, false},
		{"when", in.When, false},
		{"then", in.Then, false},
		{"verify_cmd", in.VerifyCmd, false},
		{"kata_ref", in.KataRef, false},
		{"cwe_or_owasp", in.CWEOrOWASP, false},
		{"probe_category", in.ProbeCategory, false},
		{"probe_payload", in.ProbePayload, true},
		{"expected_signal", in.ExpectedSignal, false},
	}
	for _, f := range fieldsToInspect {
		if err := InspectDistillField(f.name, f.val, f.allowNewlines); err != nil {
			return nil, err
		}
	}
	for i, trig := range in.Triggers {
		if err := InspectDistillField(fmt.Sprintf("triggers[%d]", i), trig, false); err != nil {
			return nil, err
		}
	}
	for _, rt := range in.ReqTriggers {
		if !ValidTriggerFlag(rt) {
			return nil, fmt.Errorf("%w: invalid 5-Q trigger flag %q", ErrDistillValidation, rt)
		}
	}

	// Validate explicit probe_category if supplied.
	if pc := strings.ToLower(strings.TrimSpace(in.ProbeCategory)); pc != "" {
		if _, ok := validAegisboxProbeCategories[pc]; !ok {
			return nil, fmt.Errorf("%w: unsupported aegisbox probe_category %q", ErrDistillValidation, in.ProbeCategory)
		}
	}

	// 3. Require core substance (at least title/pattern and fix).
	title := strings.TrimSpace(in.Title)
	pattern := strings.TrimSpace(in.Pattern)
	fix := strings.TrimSpace(in.Fix)
	why := strings.TrimSpace(in.Why)
	analogy := strings.TrimSpace(in.Analogy)

	if title == "" && pattern != "" {
		title = capRunes(pattern, 72)
	}
	if title == "" {
		return nil, fmt.Errorf("%w: --title or --pattern is required to distill a lesson", ErrDistillValidation)
	}
	if fix == "" {
		return nil, fmt.Errorf("%w: --fix (secure default pattern) is required to distill a lesson", ErrDistillValidation)
	}
	if why == "" {
		if pattern != "" {
			why = pattern
		} else {
			why = "Enforcing this boundary deterministically prevents the failure class from recurring."
		}
	}
	if analogy == "" {
		analogy = "Deterministic server-side boundary enforcement (like parameterized SQL queries)."
	}

	cardID := slugify(in.ID)
	if cardID == "" {
		cardID = slugify(title)
	}
	if cardID == "" {
		return nil, fmt.Errorf("%w: could not derive a valid slug id", ErrDistillValidation)
	}

	domain := mapBoundaryToDomain(in.Domain)
	if domain == "" {
		domain = "ai-app-rag"
	}

	// Prepare clean triggers for MentorCard and Keywords for AbuseCaseCriterion.
	reqFlags := inferTriggerFlags(domain, in.Triggers, in.ReqTriggers)
	cardTriggers := make([]string, 0, len(in.Triggers)+6)
	seenTrig := make(map[string]struct{})
	for _, t := range in.Triggers {
		lt := strings.ToLower(strings.TrimSpace(t))
		if lt == "" {
			continue
		}
		if _, dup := seenTrig[lt]; !dup {
			seenTrig[lt] = struct{}{}
			cardTriggers = append(cardTriggers, lt)
		}
	}
	if len(cardTriggers) == 0 {
		for _, kw := range extractKeywords(domain, title, cardID) {
			if _, dup := seenTrig[kw]; !dup {
				seenTrig[kw] = struct{}{}
				cardTriggers = append(cardTriggers, kw)
			}
		}
	}
	if len(cardTriggers) == 0 {
		cardTriggers = []string{domain}
	}
	if len(cardTriggers) > MaxMentorTriggersPerCard {
		cardTriggers = cardTriggers[:MaxMentorTriggersPerCard]
	}

	mentorCard := MentorCard{
		ID:              cardID,
		Domain:          domain,
		Triggers:        cardTriggers,
		Title:           capRunes(title, MaxMentorTitleLen),
		DeterministicEq: capRunes(analogy, MaxMentorAnalogyLen),
		SecureDefault:   capRunes(fix, MaxMentorSecureDefaultLen),
		WhyOneLiner:     capRunes(why, MaxMentorWhyOneLinerLen),
		KataRef:         slugify(in.KataRef),
		CWEOrOWASP:      strings.TrimSpace(in.CWEOrOWASP),
	}

	probeCat := inferProbeCategory(domain, in.ProbeCategory, cardTriggers, reqFlags)
	verifyCmd := strings.TrimSpace(in.VerifyCmd)
	if verifyCmd == "" {
		verifyCmd = inferVerifyCmd(domain, probeCat, reqFlags)
	}
	if err := ValidateVerifyCmd(verifyCmd); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDistillVerifyCmdBad, err)
	}

	given := strings.TrimSpace(in.Given)
	when := strings.TrimSpace(in.When)
	then := strings.TrimSpace(in.Then)
	if given == "" {
		if pattern != "" {
			given = capRunes("untrusted input attempts to trigger: "+pattern, MaxReqGWTFieldLen)
		} else {
			given = capRunes("an untrusted caller targets "+title+",", MaxReqGWTFieldLen)
		}
	}
	if when == "" {
		when = "the request reaches the application boundary,"
	}
	if then == "" {
		then = capRunes("deterministic server code enforces: "+mentorCard.SecureDefault, MaxReqGWTFieldLen)
	}

	reqID := cardID
	if !strings.HasPrefix(reqID, "req-") {
		reqID = "req-" + cardID
	}

	criterion := AbuseCaseCriterion{
		ID:          reqID,
		Triggers:    reqFlags,
		Keywords:    append([]string(nil), cardTriggers...),
		PlainTitle:  capRunes(title, MaxReqPlainTitleLen),
		Given:       capRunes(given, MaxReqGWTFieldLen),
		When:        capRunes(when, MaxReqGWTFieldLen),
		Then:        capRunes(then, MaxReqGWTFieldLen),
		WhyOneLiner: capRunes(why, MaxReqWhyLen),
		VerifyCmd:   verifyCmd,
		KataRef:     mentorCard.KataRef,
	}

	// 4. Cross-validate both artifacts through canonical manifest validators fail-closed.
	tempMentorManifest := &MentorCapsuleManifest{
		SchemaVersion: MentorSchemaVersion,
		Name:          "distilled-" + cardID,
		Version:       "1.0.0",
		Author:        "local-distill",
		CreatedAt:     time.Now().UTC(),
		AuthorityTier: TierMentorCapsule,
		Cards:         []MentorCard{mentorCard},
	}
	if err := ValidateMentorManifest(tempMentorManifest); err != nil {
		return nil, fmt.Errorf("%w: generated mentor card failed validation: %v", ErrDistillValidation, err)
	}

	tempReqManifest := &RequirementsCapsuleManifest{
		SchemaVersion: RequirementsSchemaVersion,
		Name:          "distilled-req-" + cardID,
		Version:       "1.0.0",
		Author:        "local-distill",
		CreatedAt:     time.Now().UTC(),
		AuthorityTier: TierMentorCapsule,
		Criteria:      []AbuseCaseCriterion{criterion},
	}
	if err := ValidateRequirementsManifest(tempReqManifest); err != nil {
		return nil, fmt.Errorf("%w: generated abuse-case criterion failed validation: %v", ErrDistillValidation, err)
	}

	res := &DistillResult{
		MentorCard:         mentorCard,
		AbuseCaseCriterion: criterion,
	}

	if in.IncludeProbe {
		payload := strings.TrimSpace(in.ProbePayload)
		if payload == "" {
			payload = fmt.Sprintf(`{"case_id":%q,"category":%q,"input":"sanitized-abuse-reproducer"}`, cardID, probeCat)
		}
		expectedSig := strings.TrimSpace(in.ExpectedSignal)
		if expectedSig == "" {
			expectedSig = "denied_fail_closed_zero_side_effects"
		}
		probeID := "PROBE-" + strings.ToUpper(strings.ReplaceAll(cardID, "-", "_"))
		res.AegisboxProbe = &AegisboxProbeStub{
			ProbeID:        probeID,
			Category:       probeCat,
			Payload:        payload,
			ExpectedSignal: expectedSig,
			FixPatchHint:   mentorCard.SecureDefault,
			WhyOneLiner:    mentorCard.WhyOneLiner,
		}
	}

	return res, nil
}

// WriteDistillArtifacts writes the validated MentorCard, AbuseCaseCriterion, and optional AegisboxProbeStub
// as deterministic pretty-printed JSON files inside outDir (refusing symlink targets fail-closed).
func WriteDistillArtifacts(outDir string, res *DistillResult) (*DistillWrittenFiles, error) {
	if res == nil {
		return nil, fmt.Errorf("%w: nil distill result", ErrDistillValidation)
	}
	dir := strings.TrimSpace(outDir)
	if dir == "" {
		return nil, fmt.Errorf("%w: output directory is required", ErrDistillValidation)
	}
	cleanDir := filepath.Clean(dir)
	if err := checkNoSymlinkPath(cleanDir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cleanDir, 0700); err != nil {
		return nil, fmt.Errorf("failed creating output directory %s: %w", cleanDir, err)
	}

	slug := slugify(res.MentorCard.ID)
	if slug == "" {
		slug = "distilled-lesson"
	}

	written := &DistillWrittenFiles{
		MentorCardPath: filepath.Join(cleanDir, slug+".mentor-card.json"),
		AbuseCasePath:  filepath.Join(cleanDir, slug+".abuse-case.json"),
	}

	if err := writeJSONArtifactAtomic(written.MentorCardPath, res.MentorCard); err != nil {
		return nil, err
	}
	if err := writeJSONArtifactAtomic(written.AbuseCasePath, res.AbuseCaseCriterion); err != nil {
		return nil, err
	}
	if res.AegisboxProbe != nil {
		written.ProbeStubPath = filepath.Join(cleanDir, slug+".aegisbox-probe.json")
		if err := writeJSONArtifactAtomic(written.ProbeStubPath, res.AegisboxProbe); err != nil {
			return nil, err
		}
	}

	return written, nil
}

func writeJSONArtifactAtomic(path string, v any) error {
	if err := checkNoSymlinkPath(path); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmpPath := path + ".tmp"
	if err := checkNoSymlinkPath(tmpPath); err != nil {
		return err
	}
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}
