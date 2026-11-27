package memguard

import (
	"fmt"
	"math"
	"regexp"
	"strings"
)

// InjectionRule defines a pattern-based rule for catching OWASP LLM01 Prompt Injection attacks.
type InjectionRule struct {
	ID          string
	Name        string
	Keywords    []string
	Regex       *regexp.Regexp
	Weight      float64
	Description string
}

// DetectionResult encapsulates the output of prompt injection evaluation.
type DetectionResult struct {
	IsInjected     bool
	Confidence     float64
	MatchedRuleIDs []string
	Reason         string
	Details        []string
}

// Precompiled package-level OWASP LLM01 & agentic injection rules (zero -race races).
var defaultInjectionRules = []InjectionRule{
	{
		ID:          "LLM01-001",
		Name:        "Instruction Override",
		Keywords:    []string{"ignore", "disregard", "forget", "override"},
		Regex:       regexp.MustCompile(`(?i)\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier|preceding)\s+(?:instructions|directives|prompts|rules|constraints|guidelines|context)\b`),
		Weight:      0.95,
		Description: "Direct attempt to override prior system or user instructions",
	},
	{
		ID:          "LLM01-002",
		Name:        "System Role & Chat Template Injection",
		Keywords:    []string{"im_start", "inst", "system", "sys"},
		Regex:       regexp.MustCompile(`(?i)(?:<\|im_start\|>|<\|im_end\|>|\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>|<system>|</system>|<\|system\|>|<\|user\|>|<\|assistant\|>)`),
		Weight:      0.90,
		Description: "Artificial chat-template or system prompt boundary injection",
	},
	{
		ID:          "LLM01-003",
		Name:        "Jailbreak & Unrestricted Persona Escalation",
		Keywords:    []string{"developer mode", "jailbreak", "unrestricted", "guardrails"},
		Regex:       regexp.MustCompile(`(?i)\b(?:you\s+are\s+now\s+in\s+developer\s+mode|dan\s+mode|jailbreak(?:\s+mode)?|unrestricted\s+(?:ai|root|mode)|act\s+as\s+(?:an?\s+)?unrestricted\s+root|disable\s+(?:all\s+)?safety\s+filters|bypass\s+(?:all\s+)?guardrails|ignore\s+security\s+policy)\b`),
		Weight:      0.95,
		Description: "Attempt to switch agent into unrestricted or developer jailbreak mode",
	},
	{
		ID:          "LLM01-004",
		Name:        "Credential & Secret Exfiltration Directive",
		Keywords:    []string{"exfiltrate", "secrets", "id_ed25519", "id_rsa", "passwd"},
		Regex:       regexp.MustCompile(`(?i)(?:\bexfiltrate\b|\bsend\s+(?:all\s+)?(?:secrets|keys|passwords|credentials|env|tokens)\s+to\b|\bcat\s+(?:~\/\.ssh\/id_[a-z0-9_]+|\/etc\/passwd|\/etc\/shadow|\.env)\b|\bcurl\s+[^\n]*https?://(?:webhook\.site|pipedream|requestbin|ngrok|evil\.example))`),
		Weight:      0.90,
		Description: "Directive attempting to read or exfiltrate sensitive credentials",
	},
	{
		ID:          "LLM01-005",
		Name:        "XML Tool Reflection & Fence Breakout",
		Keywords:    []string{"tool_call", "function_call", "untrusted_artifact", "root_exec"},
		Regex:       regexp.MustCompile(`(?i)</?(?:tool_call|tool_response|tool_results|function_call|call_tool|untrusted_artifact|openclaw_execute|control_panel|system_override|root_exec|admin_[a-z0-9_-]+|system_[a-z0-9_-]+)(?:\s+[^>]*)?>`),
		Weight:      0.95,
		Description: "Forged XML tool-call reflection or untrusted_artifact fence breakout",
	},
	{
		ID:          "LLM01-006",
		Name:        "Hostile Shell Command Injection",
		Keywords:    []string{"bash -c", "sh -c", "rm -rf", "curl"},
		Regex:       regexp.MustCompile(`(?i)(?:\b(?:ba)?sh\s+-c\s+["']?(?:curl|wget|rm\s+-rf|nc\b|python|perl)|\|\s*(?:ba)?sh\b|\brm\s+-rf\s+/\b|/dev/tcp/)`),
		Weight:      0.85,
		Description: "Embedded hostile shell execution payload",
	},
	{
		ID:          "LLM01-007",
		Name:        "Localhost / WebSocket Control Pivot",
		Keywords:    []string{"ws://", "wss://", "127.0.0.1", "localhost", "169.254.169.254"},
		Regex:       regexp.MustCompile(`(?i)(?:\bwss?://(?:127(?:\.\d{1,3}){3}|localhost|\[::1\]|0\.0\.0\.0)(?::\d{1,5})?|\bhttps?://169\.254\.169\.254/latest/meta-data)`),
		Weight:      0.85,
		Description: "Localhost WebSocket or cloud metadata control-plane pivot attempt",
	},
	{
		ID:          "LLM01-008",
		Name:        "System Prompt Extraction",
		Keywords:    []string{"system prompt", "repeat", "reveal"},
		Regex:       regexp.MustCompile(`(?i)\b(?:reveal|print|dump|output|leak|repeat)\s+(?:your\s+|the\s+)?(?:hidden\s+|full\s+)?(?:system\s+prompt|initial\s+instructions|system\s+instructions)\b`),
		Weight:      0.80,
		Description: "Attempt to extract hidden system prompt instructions",
	},
	{
		ID:          "LLM01-009",
		Name:        "Persistent Memory Poisoning Directive",
		Keywords:    []string{"remember forever", "override all future", "persist this instruction"},
		Regex:       regexp.MustCompile(`(?i)\b(?:remember\s+forever\s+that|override\s+all\s+future\s+(?:sessions|instructions|agents)|persist\s+this\s+(?:instruction|override)\s+(?:in|to)\s+memory)\b`),
		Weight:      0.85,
		Description: "Explicit cross-session cognitive memory poisoning instruction",
	},
}

// Detector scans content using static OWASP LLM01 rules and normalization telemetry.
type Detector struct {
	rules []InjectionRule
}

// NewDetector initializes a prompt injection detector with standard precompiled rules.
func NewDetector() *Detector {
	return &Detector{
		rules: defaultInjectionRules,
	}
}

// Scan normalizes and evaluates content for prompt injection and cloaked attacks.
func (d *Detector) Scan(content string) *DetectionResult {
	normRes := Normalize(content)
	return d.ScanNormalized(content, normRes)
}

// ScanNormalized evaluates already-normalized content to avoid redundant normalization passes.
func (d *Detector) ScanNormalized(content string, normRes *NormalizationResult) *DetectionResult {
	if normRes == nil {
		normRes = Normalize(content)
	}

	res := &DetectionResult{}
	seenRules := make(map[string]struct{})

	scanTarget := func(label, text string, isCloaked bool) {
		if strings.TrimSpace(text) == "" {
			return
		}
		for _, rule := range d.rules {
			if rule.Regex.MatchString(text) {
				if _, exists := seenRules[rule.ID]; !exists {
					seenRules[rule.ID] = struct{}{}
					res.MatchedRuleIDs = append(res.MatchedRuleIDs, rule.ID)
				}
				weight := rule.Weight
				if isCloaked && weight < 0.95 {
					weight = 0.95
				}
				if weight > res.Confidence {
					res.Confidence = weight
				}
				res.Details = append(res.Details, fmt.Sprintf("%s matched %s (%s)", label, rule.ID, rule.Name))
				if isCloaked {
					if _, exists := seenRules["CLOAK-001"]; !exists {
						seenRules["CLOAK-001"] = struct{}{}
						res.MatchedRuleIDs = append(res.MatchedRuleIDs, "CLOAK-001")
						res.Details = append(res.Details, fmt.Sprintf("%s contained cloaked injection payload", label))
					}
				}
			}
		}
	}

	scanTarget("cleaned", normRes.Cleaned, false)
	for i, unwrapped := range normRes.UnwrappedContent {
		scanTarget(fmt.Sprintf("unwrapped[%d]", i), unwrapped, false)
	}
	for i, decoded := range normRes.DecodedPayloads {
		scanTarget(fmt.Sprintf("decoded[%d]", i), decoded, true)
	}

	if res.Confidence >= 0.75 || len(res.MatchedRuleIDs) > 0 {
		res.IsInjected = res.Confidence >= 0.75
		res.Reason = strings.Join(res.Details, "; ")
	}
	return res
}

// TermVector represents normalized term frequencies for cosine similarity scoring.
type TermVector map[string]float64

// IntentDriftScore holds the computed drift metrics between declared intent and payload.
type IntentDriftScore struct {
	DriftDetected   bool
	Similarity      float64
	ImperativeScore float64
	Reason          string
}

var (
	wordTokenRe = regexp.MustCompile(`[a-zA-Z0-9_]{2,}`)

	imperativeHijackPhrases = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(?:must\s+immediately|always\s+execute|never\s+tell\s+the\s+user|silently\s+(?:run|execute|send|upload|post))\b`),
		regexp.MustCompile(`(?i)\b(?:you\s+must\s+now|from\s+now\s+on\s+you\s+(?:are|will|must)|new\s+system\s+directive)\b`),
		regexp.MustCompile(`(?i)\b(?:do\s+not\s+follow\s+(?:the\s+)?user|prioritize\s+this\s+instruction\s+over)\b`),
	}
)

var stopWords = map[string]bool{
	"the": true, "and": true, "for": true, "with": true, "that": true,
	"this": true, "from": true, "are": true, "was": true, "were": true,
	"have": true, "has": true, "not": true, "but": true, "into": true,
}

func buildTermVector(text string) TermVector {
	vec := make(TermVector)
	tokens := wordTokenRe.FindAllString(strings.ToLower(text), -1)
	for _, tok := range tokens {
		if stopWords[tok] {
			continue
		}
		vec[tok]++
	}
	var normSq float64
	for _, v := range vec {
		normSq += v * v
	}
	if normSq > 0 {
		inv := 1.0 / math.Sqrt(normSq)
		for k, v := range vec {
			vec[k] = v * inv
		}
	}
	return vec
}

// CosineSimilarity computes the cosine similarity between two normalized term vectors.
func CosineSimilarity(v1, v2 TermVector) float64 {
	if len(v1) == 0 || len(v2) == 0 {
		return 0.0
	}
	var dot float64
	for k, a := range v1 {
		if b, ok := v2[k]; ok {
			dot += a * b
		}
	}
	if dot < 0 {
		return 0
	}
	if dot > 1 {
		return 1
	}
	return dot
}

// AnalyzeIntentDrift evaluates whether untrusted content departs from declared task intent
// and pivots into imperative command hijacking.
func AnalyzeIntentDrift(taskIntent, content string) *IntentDriftScore {
	score := &IntentDriftScore{}
	if strings.TrimSpace(content) == "" {
		return score
	}

	if strings.TrimSpace(taskIntent) != "" {
		score.Similarity = CosineSimilarity(buildTermVector(taskIntent), buildTermVector(content))
	}

	hits := 0
	for _, re := range imperativeHijackPhrases {
		if re.MatchString(content) {
			hits++
		}
	}
	if hits > 0 {
		score.ImperativeScore = math.Min(1.0, 0.55+0.25*float64(hits))
	}

	if score.ImperativeScore >= 0.75 && score.Similarity < 0.20 {
		score.DriftDetected = true
		score.Reason = fmt.Sprintf("imperative intent drift detected (imperative=%.2f similarity=%.2f)", score.ImperativeScore, score.Similarity)
	}
	return score
}
