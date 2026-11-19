package security

import (
	"errors"
	"regexp"
	"strings"

	"golang.org/x/text/unicode/norm"
)

var (
	// ErrPromptInjectionRejected is returned when untrusted input contains explicit prompt injection or jailbreak payloads.
	ErrPromptInjectionRejected = errors.New("cognitive firewall violation: detected prompt injection or jailbreak attempt in untrusted memory")
)

// InjectionPattern models an adversarial prompt injection pattern.
type InjectionPattern struct {
	Name       string
	Regex      *regexp.Regexp
	TaintScore float64
	IsCritical bool
}

var injectionPatterns = []InjectionPattern{
	{
		Name:       "Instruction Override",
		Regex:      regexp.MustCompile(`(?i)\b(?:ignore|disregard|forget|override)\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|directives|prompts|rules|constraints)\b`),
		TaintScore: 0.95,
		IsCritical: true,
	},
	{
		Name:       "System Delimiter Injection",
		Regex:      regexp.MustCompile(`(?i)(?:<\|im_start\|>|<\|im_end\|>|\[INST\]|\[/INST\]|<system>|</system>|<\|system\|>|<\|user\|>|<\|assistant\|>)`),
		TaintScore: 0.90,
		IsCritical: true,
	},
	{
		Name:       "Developer/Jailbreak Mode",
		Regex:      regexp.MustCompile(`(?i)\b(?:you\s+are\s+now\s+in\s+developer\s+mode|dan\s+mode|jailbreak(?:\s+mode)?|unrestricted\s+ai|disable\s+(?:all\s+)?safety\s+filters|bypass\s+all\s+guardrails)\b`),
		TaintScore: 0.95,
		IsCritical: true,
	},
	{
		Name:       "Exfiltration Directive",
		Regex:      regexp.MustCompile(`(?i)\b(?:exfiltrate|send\s+(?:all\s+)?(?:secrets|keys|passwords|env|tokens)\s+to|curl\s+-[A-Za-z0-9\s]*http[s]?://(?:webhook\.site|pipedream|requestbin|ngrok))\b`),
		TaintScore: 0.85,
		IsCritical: true,
	},
	{
		Name:       "Roleplay Privilege Escalation",
		Regex:      regexp.MustCompile(`(?i)\b(?:act\s+as\s+root|sudo\s+mode\s+enabled|you\s+have\s+full\s+unrestricted\s+access|ignore\s+security\s+policy)\b`),
		TaintScore: 0.75,
		IsCritical: false,
	},
	{
		Name:       "XML Tool Reflection & Delimiter Smuggling",
		Regex:      regexp.MustCompile(`(?i)<\/?(?:tool_call|tool_response|tool_results|function_call|call_tool|result|observation|thought|antml|untrusted_artifact|openclaw_execute|control_panel|system_override|root_exec|admin_[a-z0-9_-]+|system_[a-z0-9_-]+)(?:\s+[^>]*)?>`),
		TaintScore: 0.95,
		IsCritical: true,
	},
}

var xmlDelimiterRegex = regexp.MustCompile(`(?i)<\/?(?:tool_call|tool_response|tool_results|function_call|call_tool|result|observation|thought|antml|untrusted_artifact|untrusted_code_artifact|untrusted_external_artifact|untrusted_[a-z0-9_-]+|openclaw_execute|control_panel|system_override|root_exec|admin_[a-z0-9_-]+|system_[a-z0-9_-]+|system|admin|instruction|developer|prompt|context|assistant|user)(?:\s+[^>]*)?>`)

// SanitizeXMLDelimiters strips artificial prompt-injection delimiters and XML tool reflection tags.
func SanitizeXMLDelimiters(text string) (string, int) {
	// Normalize NFKC to avoid Unicode obfuscation
	normalized := norm.NFKC.String(text)
	var clean strings.Builder
	for _, r := range normalized {
		if (r >= 0x200B && r <= 0x200F) || r == 0xFEFF {
			continue
		}
		clean.WriteRune(r)
	}
	cleaned := clean.String()
	count := 0
	for pass := 0; pass < 8; pass++ {
		before := cleaned
		if strings.IndexByte(cleaned, '<') >= 0 {
			cleaned = xmlDelimiterRegex.ReplaceAllStringFunc(cleaned, func(m string) string {
				count++
				return " "
			})
		}
		if cleaned == before {
			break
		}
	}
	return strings.TrimSpace(cleaned), count
}

// FirewallResult encapsulates the cognitive firewall evaluation.
type FirewallResult struct {
	TaintScore float64  `json:"taint_score"`
	Flags      []string `json:"flags,omitempty"`
	IsCritical bool     `json:"is_critical"`
}

// InspectCognitiveThreats scans text for prompt injection, jailbreaks, and adversarial manipulation.
func InspectCognitiveThreats(text string) (*FirewallResult, error) {
	// Normalize NFKC to avoid Unicode obfuscation
	normalized := norm.NFKC.String(text)

	// Strip zero-width runes before regex scanning
	var clean strings.Builder
	for _, r := range normalized {
		if (r >= 0x200B && r <= 0x200F) || r == 0xFEFF {
			continue
		}
		clean.WriteRune(r)
	}
	cleanText := clean.String()

	res := &FirewallResult{
		TaintScore: 0.0,
		Flags:      make([]string, 0),
		IsCritical: false,
	}

	for _, pat := range injectionPatterns {
		if pat.Regex.MatchString(cleanText) {
			res.Flags = append(res.Flags, pat.Name)
			if pat.TaintScore > res.TaintScore {
				res.TaintScore = pat.TaintScore
			}
			if pat.IsCritical {
				res.IsCritical = true
			}
		}
	}

	return res, nil
}
