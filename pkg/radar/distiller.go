package radar

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/bonjoski/coppermind/pkg/authz"
	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/security"
	"golang.org/x/text/unicode/norm"
)

var (
	injectionRegex = regexp.MustCompile(`(?i)(ignore\s+(all\s+)?(previous|prior)\s+instructions|system\s+directive|disregard\s+security\s+rules|<system_directive>|<untrusted_artifact|<\/untrusted_artifact>|<recalled_context>)`)
)

// DistillItem transforms a RawItem into a sanitized, typed RadarFact.
func DistillItem(item RawItem, feed FeedConfig) (*RadarFact, error) {
	// 1. NFKC normalization and zero-width rune stripping
	normTitle := sanitizeRunes(item.Title)
	normBody := sanitizeRunes(item.RawBody)

	// 2. Secret & Credential Quarantine (Stormcage / Locksmith)
	secBody, err := security.SanitizeMemory(normBody)
	if err != nil {
		normBody = "[REDACTED_SECURITY_POLICY_VIOLATION]"
	} else {
		normBody = secBody.SanitizedText
	}

	// 3. Cognitive Firewall: Neutralize prompt injection attempts (OWASP LLM01)
	if injectionRegex.MatchString(normBody) || injectionRegex.MatchString(normTitle) {
		normBody = injectionRegex.ReplaceAllString(normBody, "[NEUTRALIZED_PROMPT_INJECTION_ATTEMPT]")
		normTitle = injectionRegex.ReplaceAllString(normTitle, "[NEUTRALIZED_PROMPT_INJECTION_ATTEMPT]")
	}

	// 4. Determine deterministic ID: SHA256(feed_id + ":" + external_id)
	h := sha256.Sum256([]byte(fmt.Sprintf("%s:%s", feed.ID, item.ExternalID)))
	factID := fmt.Sprintf("rf_%s", hex.EncodeToString(h[:8]))

	// 5. Categorize and infer technology
	category := CategoryStandard
	severity := SeverityInfo
	advisoryID := item.ExternalID

	lowerTitle := strings.ToLower(normTitle)
	lowerBody := strings.ToLower(normBody)

	if strings.Contains(normTitle, "CVE-") || strings.Contains(normTitle, "GHSA-") || strings.Contains(lowerTitle, "vulnerab") {
		category = CategoryVulnerability
		severity = SeverityHigh
	} else if strings.Contains(lowerTitle, "deprecat") || strings.Contains(lowerBody, "deprecat") {
		category = CategoryDeprecation
		severity = SeverityMedium
	} else if strings.Contains(lowerTitle, "exploit") || strings.Contains(lowerBody, "bypass") || strings.Contains(lowerBody, "jailbreak") {
		category = CategoryExploitPrimitive
		severity = SeverityCritical
	}

	if feed.SeverityThreshold != "" {
		severity = feed.SeverityThreshold
	}

	// Extract technology name heuristics
	tech := feed.Ecosystem
	if strings.Contains(normTitle, "Go ") || strings.Contains(lowerBody, "golang") {
		tech = "golang"
	} else if strings.Contains(normTitle, "Rust") || strings.Contains(lowerBody, "cargo") {
		tech = "rust"
	} else if strings.Contains(normTitle, "Spring") {
		tech = "spring"
	} else if strings.Contains(normTitle, "Node") || strings.Contains(lowerBody, "npm") {
		tech = "node"
	} else if strings.Contains(normTitle, ".NET") || strings.Contains(lowerBody, "c#") {
		tech = "dotnet"
	}

	summary := normTitle
	if len(summary) > 200 {
		summary = summary[:197] + "..."
	}

	effDate := item.PublishedAt.Format("2006-01-02")
	if effDate == "" || effDate == "0001-01-01" {
		effDate = time.Now().UTC().Format("2006-01-02")
	}

	return &RadarFact{
		ID:            factID,
		FeedID:        feed.ID,
		Ecosystem:     feed.Ecosystem,
		Technology:    tech,
		Category:      category,
		AdvisoryID:    advisoryID,
		Severity:      severity,
		Summary:       summary,
		Evidence:      normBody,
		EffectiveDate: effDate,
		ProvenanceURL: item.URL,
		AuthorityTier: authz.TierName3Episodic, // Epistemic Tier 3.5 invariant
		CreatedAt:     time.Now().UTC(),
	}, nil
}

// ToRememberRequest converts a RadarFact into an epistemic memory request.
func (f *RadarFact) ToRememberRequest(sessionID string) brain.RememberRequest {
	if sessionID == "" {
		sessionID = fmt.Sprintf("radar-%s", f.Ecosystem)
	}

	content := fmt.Sprintf("[%s] %s (Ecosystem: %s, Category: %s, Severity: %s, Date: %s)\n%s\nURL: %s",
		f.AdvisoryID, f.Summary, f.Ecosystem, f.Category, f.Severity, f.EffectiveDate, f.Evidence, f.ProvenanceURL)

	metadata := map[string]string{
		"radar_id":       f.ID,
		"feed_id":        f.FeedID,
		"ecosystem":      f.Ecosystem,
		"technology":     f.Technology,
		"category":       f.Category,
		"advisory_id":    f.AdvisoryID,
		"severity":       f.Severity,
		"effective_date": f.EffectiveDate,
		"provenance_url": f.ProvenanceURL,
	}

	return brain.RememberRequest{
		SessionID:       sessionID,
		Category:        "industry_radar",
		Content:         content,
		Provenance:      brain.ProvenanceUntrustedWeb,
		AuthorityTier:   authz.TierName3Episodic,
		LifecycleStatus: string(authz.StatusActive),
		AuthorRole:      "radar-harvester",
		Metadata:        metadata,
	}
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
