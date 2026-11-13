package security

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
	"unicode"
)

var (
	// ErrSecretRejected is returned when a payload is determined to be a raw credential or private key.
	ErrSecretRejected = errors.New("security policy violation: storing raw credentials or private keys in Coppermind memory is strictly forbidden")
)

// SecretPattern defines a curated signature for credentials.
type SecretPattern struct {
	Name        string
	Regex       *regexp.Regexp
	IsCritical  bool // Critical patterns (e.g. private keys) cause immediate rejection if dominant
	Replacement string
}

var builtinPatterns = []SecretPattern{
	{
		Name:        "Private Key Block",
		Regex:       regexp.MustCompile(`-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED|ED25519) )?PRIVATE KEY-----[\s\S]+?-----END (?:(?:RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED|ED25519) )?PRIVATE KEY-----`),
		IsCritical:  true,
		Replacement: "[REDACTED_PRIVATE_KEY]",
	},
	{
		Name:        "AWS Access Key ID",
		Regex:       regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`),
		IsCritical:  false,
		Replacement: "[REDACTED_AWS_KEY]",
	},
	{
		Name:        "Anthropic API Key",
		Regex:       regexp.MustCompile(`\bsk-ant-[a-zA-Z0-9_\-]{20,}\b`),
		IsCritical:  false,
		Replacement: "[REDACTED_ANTHROPIC_KEY]",
	},
	{
		Name:        "OpenAI API Key",
		Regex:       regexp.MustCompile(`\bsk-(?:proj-|svcacct-|admin-)?[a-zA-Z0-9_\-]{20,}\b`),
		IsCritical:  false,
		Replacement: "[REDACTED_OPENAI_KEY]",
	},
	{
		Name:        "Google API Key",
		Regex:       regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`),
		IsCritical:  false,
		Replacement: "[REDACTED_GOOGLE_KEY]",
	},
	{
		Name:        "GitHub Personal/App Token",
		Regex:       regexp.MustCompile(`\bgh[pousr]_[a-zA-Z0-9]{36,255}\b`),
		IsCritical:  false,
		Replacement: "[REDACTED_GITHUB_TOKEN]",
	},
	{
		Name:        "GitHub Fine-Grained Token",
		Regex:       regexp.MustCompile(`\bgithub_pat_[a-zA-Z0-9_]{22,255}\b`),
		IsCritical:  false,
		Replacement: "[REDACTED_GITHUB_PAT]",
	},
	{
		Name:        "Slack Token",
		Regex:       regexp.MustCompile(`\bxox[baprs]-[0-9a-zA-Z\-]{10,128}\b`),
		IsCritical:  false,
		Replacement: "[REDACTED_SLACK_TOKEN]",
	},
	{
		Name:        "JSON Web Token",
		Regex:       regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b`),
		IsCritical:  false,
		Replacement: "[REDACTED_JWT]",
	},
	{
		Name:        "Database Connection Password",
		Regex:       regexp.MustCompile(`\b((?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|rediss|amqp|amqps):\/\/[^:\s]+:)([^@\s]+)(@[^\s"']+\b)`),
		IsCritical:  false,
		Replacement: "${1}[REDACTED_PASSWORD]${3}",
	},
	{
		Name:        "Bearer Authorization Token",
		Regex:       regexp.MustCompile(`(?i)\b(Bearer\s+)[A-Za-z0-9\-._~+/]{16,}=*`),
		IsCritical:  false,
		Replacement: "${1}[REDACTED_BEARER_TOKEN]",
	},
	{
		Name:        "Generic Quoted Secret Assignment",
		Regex:       regexp.MustCompile(`(?i)\b((?:api[_-]?key|secret(?:[_-]?key)?|password|passwd|pwd|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)\s*[:=]\s*["'])([^"'\r\n]{8,})(["'])`),
		IsCritical:  false,
		Replacement: "${1}[REDACTED_CREDENTIAL]${3}",
	},
}

// SanitizationResult holds the output of secret redaction.
type SanitizationResult struct {
	SanitizedText  string
	RedactedCount  int
	DetectedTypes  []string
	RejectedReason string
}

// SanitizeMemory evaluates input text for secrets, stripping or rejecting credentials.
func SanitizeMemory(input string) (*SanitizationResult, error) {
	trimmed := strings.TrimSpace(input)
	if len(trimmed) == 0 {
		return &SanitizationResult{SanitizedText: input}, nil
	}

	result := &SanitizationResult{
		SanitizedText: input,
	}

	// 1. Check for standalone critical secrets (e.g. raw private key)
	if strings.Contains(input, "-----BEGIN") && strings.Contains(input, "PRIVATE KEY-----") {
		// If the entire text or majority is a private key, fail-closed reject
		if len(trimmed) < 4096 {
			return nil, fmt.Errorf("%w: private key block detected", ErrSecretRejected)
		}
	}

	// 2. Check for standalone high-entropy token (e.g. raw token passed directly as content)
	tokens := strings.Fields(trimmed)
	if len(tokens) == 1 && len(trimmed) >= 24 && ShannonEntropy(trimmed) >= 4.2 {
		return nil, fmt.Errorf("%w: raw high-entropy secret detected", ErrSecretRejected)
	}

	// 3. Regex redaction of known credential signatures
	for _, p := range builtinPatterns {
		if p.Regex.MatchString(result.SanitizedText) {
			matches := p.Regex.FindAllString(result.SanitizedText, -1)
			result.RedactedCount += len(matches)
			result.DetectedTypes = append(result.DetectedTypes, p.Name)
			result.SanitizedText = p.Regex.ReplaceAllString(result.SanitizedText, p.Replacement)
		}
	}

	// 4. Entropy scanning on unredacted long words/tokens
	words := strings.Fields(result.SanitizedText)
	for _, word := range words {
		if strings.Contains(word, "[REDACTED_") {
			continue
		}
		cleaned := strings.Trim(word, `"',;:=()[]{}<>`)
		if len(cleaned) >= 32 && ShannonEntropy(cleaned) >= 4.5 {
			// Suspected raw cryptographic token that evaded regex
			result.SanitizedText = strings.ReplaceAll(result.SanitizedText, cleaned, "[REDACTED_HIGH_ENTROPY_SECRET]")
			result.RedactedCount++
			result.DetectedTypes = append(result.DetectedTypes, "High-Entropy Secret")
		}
	}

	return result, nil
}

// ShannonEntropy calculates the bits of entropy per character.
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}
	freq := make(map[rune]float64)
	runeCount := 0
	for _, r := range s {
		if unicode.IsGraphic(r) {
			freq[r]++
			runeCount++
		}
	}
	if runeCount == 0 {
		return 0.0
	}

	total := float64(runeCount)
	var entropy float64
	for _, count := range freq {
		p := count / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}
