package lenses

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/router"
	"github.com/bonjoski/coppermind/pkg/security"
	"golang.org/x/text/unicode/norm"
)

// EnforcePoCGate ensures findings have actionable, reproducible proof before alerting.
// Returns true for info or low severity findings.
// For medium, high, critical, requires a non-empty, actionable PoC (>= 15 characters,
// not placeholder/todo/na, containing executable structures such as curl, http, {}, (), $).
// If a medium/high/critical finding fails the PoC gate, demotes severity to info,
// sets UnverifiedPoC = true, and returns false.
func EnforcePoCGate(f *Finding) bool {
	if f == nil {
		return false
	}

	sev := strings.ToLower(strings.TrimSpace(f.Severity))
	if sev == "info" || sev == "low" {
		return true
	}

	cleanPoC := strings.TrimSpace(f.PoC)
	if len(cleanPoC) < 15 {
		f.Severity = "info"
		f.UnverifiedPoC = true
		return false
	}

	lower := strings.ToLower(cleanPoC)
	if strings.Contains(lower, "todo") || strings.Contains(lower, "n/a") || strings.Contains(lower, "not applicable") {
		f.Severity = "info"
		f.UnverifiedPoC = true
		return false
	}

	// Must contain a verifiable command or payload structure
	hasExecutableStructure := strings.Contains(lower, "curl") ||
		strings.Contains(lower, "http") ||
		strings.Contains(cleanPoC, "{") ||
		strings.Contains(cleanPoC, "()") ||
		(strings.Contains(cleanPoC, "(") && strings.Contains(cleanPoC, ")")) ||
		strings.Contains(cleanPoC, "$")

	if !hasExecutableStructure {
		f.Severity = "info"
		f.UnverifiedPoC = true
		return false
	}

	return true
}

// ComputeDedupHash calculates a deterministic idempotency key for an observation:
// SHA256(project + ":" + lens_name + ":" + target_memory_hash + ":" + observation_fingerprint)
func ComputeDedupHash(project, lensName, targetHash, summary string) string {
	cleanSummary := strings.ToLower(strings.TrimSpace(summary))
	raw := fmt.Sprintf("%s:%s:%s:%s", project, lensName, targetHash, cleanSummary)
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// EvaluateCandidate invokes LiteLLM through the model router and parses structured findings.
func EvaluateCandidate(ctx context.Context, lens *LensConfig, candidate *brain.MemoryNode, contextMemories []*brain.MemoryNode, rtr router.ModelRouter) (*ModelResponse, error) {
	if rtr == nil {
		return nil, fmt.Errorf("model router is not available")
	}

	sysPrompt, userPrompt := BuildEvaluationPrompt(lens, candidate, contextMemories)

	modelName := lens.Model
	if modelName == "" {
		modelName = "default"
	}

	req := &router.CompletionRequest{
		Model: modelName,
		Messages: []router.Message{
			{Role: "system", Content: sysPrompt},
			{Role: "user", Content: userPrompt},
		},
		Temperature: 0.1, // Low temperature for deterministic analysis
		MaxTokens:   2048,
	}

	resp, err := rtr.Complete(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("model completion failed for lens %q: %w", lens.Name, err)
	}

	modelResp, err := parseAndSanitizeResponse(resp.Content)
	if err != nil {
		return nil, err
	}

	// For security-architect lens, enforce PoC gate across all findings
	if lens != nil && lens.Name == "security-architect" {
		for i := range modelResp.Findings {
			EnforcePoCGate(&modelResp.Findings[i])
		}
	}

	return modelResp, nil
}

// parseAndSanitizeResponse parses the model output, enforces structured JSON, and runs secret quarantine.
func parseAndSanitizeResponse(content string) (*ModelResponse, error) {
	jsonStr := extractJSON(content)
	if jsonStr == "" {
		return &ModelResponse{Findings: []Finding{}}, nil
	}

	var parsed ModelResponse
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		// Attempt parsing as array directly: [{"severity": ...}]
		var arrayFindings []Finding
		if arrErr := json.Unmarshal([]byte(jsonStr), &arrayFindings); arrErr == nil {
			parsed.Findings = arrayFindings
		} else {
			return nil, fmt.Errorf("failed to parse structured JSON findings: %w (raw: %s)", err, jsonStr)
		}
	}

	var sanitizedFindings []Finding
	for _, f := range parsed.Findings {
		// 1. Severity validation
		sev := strings.ToLower(strings.TrimSpace(f.Severity))
		switch sev {
		case "info", "low", "medium", "high", "critical":
			f.Severity = sev
		default:
			f.Severity = "medium"
		}

		// 2. NFKC Normalization & Zero-width rune stripping
		normSummary := sanitizeRunes(f.Summary)
		normEvidence := sanitizeRunes(f.Evidence)
		normEntryPoint := sanitizeRunes(f.EntryPoint)
		normSiblingInconsistency := sanitizeRunes(f.SiblingInconsistency)
		normPoC := sanitizeRunes(f.PoC)

		// 3. Secret & Credential Quarantine (Fail-closed or redact)
		secSum, err := security.SanitizeMemory(normSummary)
		if err != nil {
			// If summary itself contains a raw private key, drop it or mark redacted
			f.Summary = "[REDACTED_SECURITY_POLICY_VIOLATION]"
		} else {
			f.Summary = secSum.SanitizedText
		}

		secEv, err := security.SanitizeMemory(normEvidence)
		if err != nil {
			f.Evidence = "[REDACTED_PRIVATE_KEY]"
		} else {
			f.Evidence = secEv.SanitizedText
		}

		secPoC, err := security.SanitizeMemory(normPoC)
		if err != nil {
			f.PoC = "[REDACTED_PRIVATE_KEY]"
		} else {
			f.PoC = secPoC.SanitizedText
		}

		f.EntryPoint = normEntryPoint
		f.SiblingInconsistency = normSiblingInconsistency

		// 4. Enforce PoC gate for differential security findings
		if f.Category == "differential_auth" || f.Category == "unintended_side_effect" || f.Category == "sink_injection" {
			EnforcePoCGate(&f)
		}

		if strings.TrimSpace(f.Summary) != "" {
			sanitizedFindings = append(sanitizedFindings, f)
		}
	}

	return &ModelResponse{Findings: sanitizedFindings}, nil
}

// extractJSON finds JSON object or array within possible markdown blocks or conversational text.
func extractJSON(s string) string {
	s = strings.TrimSpace(s)
	// Check for markdown code fences: ```json ... ``` or ``` ... ```
	if startIdx := strings.Index(s, "```json"); startIdx != -1 {
		rest := s[startIdx+7:]
		if endIdx := strings.Index(rest, "```"); endIdx != -1 {
			return strings.TrimSpace(rest[:endIdx])
		}
	} else if startIdx := strings.Index(s, "```"); startIdx != -1 {
		rest := s[startIdx+3:]
		if endIdx := strings.Index(rest, "```"); endIdx != -1 {
			return strings.TrimSpace(rest[:endIdx])
		}
	}

	// Find outermost { ... }
	firstBrace := strings.Index(s, "{")
	lastBrace := strings.LastIndex(s, "}")
	if firstBrace != -1 && lastBrace != -1 && lastBrace > firstBrace {
		return s[firstBrace : lastBrace+1]
	}

	// Find outermost [ ... ]
	firstBracket := strings.Index(s, "[")
	lastBracket := strings.LastIndex(s, "]")
	if firstBracket != -1 && lastBracket != -1 && lastBracket > firstBracket {
		return s[firstBracket : lastBracket+1]
	}

	return ""
}

func sanitizeRunes(input string) string {
	normalized := norm.NFKC.String(input)
	var sb strings.Builder
	for _, r := range normalized {
		if (r >= 0x200B && r <= 0x200F) || r == 0xFEFF || (r < 0x20 && r != '\n' && r != '\t' && r != '\r') {
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}
