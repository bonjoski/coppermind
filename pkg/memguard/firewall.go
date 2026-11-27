package memguard

import (
	"fmt"
	"strings"
	"time"
)

// Decision describes the enforcement action chosen by the cognitive firewall.
type Decision string

const (
	DecisionAllowed     Decision = "allowed"
	DecisionSanitized   Decision = "sanitized"
	DecisionQuarantined Decision = "quarantined"

	// VerdictAllow and VerdictPoisoned provide semantic aliases for firewall decisions.
	VerdictAllow    Decision = DecisionAllowed
	VerdictPoisoned Decision = DecisionQuarantined
)

// Verdict summarizes the cognitive firewall security evaluation of a memory record.
type Verdict struct {
	Status         Decision   `json:"status"`
	Reason         string     `json:"reason,omitempty"`
	Taint          TaintLevel `json:"taint"`
	CleanedContent string     `json:"cleaned_content,omitempty"`
	RiskScore      float64    `json:"risk_score"`
	MatchedRules   []string   `json:"matched_rules,omitempty"`
	Details        []string   `json:"details,omitempty"`
	LatencyMs      float64    `json:"latency_ms"`
	Cached         bool       `json:"cached"`
}

// Firewall coordinates multi-tier normalization, OWASP LLM01 static detection,
// intent-drift scoring, pre-flight sanitization, and SHA-256 verdict caching.
type Firewall struct {
	detector  *Detector
	sanitizer *PreFlightSanitizer
	cache     *VerdictCache
}

// NewFirewall initializes a concurrency-safe cognitive memory Firewall.
func NewFirewall() *Firewall {
	return &Firewall{
		detector:  NewDetector(),
		sanitizer: NewPreFlightSanitizer(),
		cache:     NewVerdictCache(4096),
	}
}

// Gate evaluates a MemoryRecord against targetPrivilege and returns a fail-closed Verdict.
func (f *Firewall) Gate(record *MemoryRecord, targetPrivilege PrivilegeLevel) *Verdict {
	start := time.Now()
	if record == nil {
		return &Verdict{
			Status:       DecisionQuarantined,
			Reason:       "nil memory record rejected fail-closed",
			Taint:        TAINT_UNTRUSTED_WEB,
			RiskScore:    1.0,
			MatchedRules: []string{"SCHEMA-NIL"},
			LatencyMs:    float64(time.Since(start).Microseconds()) / 1000.0,
		}
	}

	effectiveTaint := record.Taint
	if !effectiveTaint.IsValid() {
		effectiveTaint = TAINT_UNTRUSTED_WEB
	}

	if len(record.Content) > MaxContentLength {
		return &Verdict{
			Status:       DecisionQuarantined,
			Reason:       ErrContentTooLarge.Error(),
			Taint:        effectiveTaint,
			RiskScore:    1.0,
			MatchedRules: []string{"SCHEMA-SIZE"},
			LatencyMs:    float64(time.Since(start).Microseconds()) / 1000.0,
		}
	}

	cacheKey := HashKey(string(effectiveTaint), string(targetPrivilege), record.TaskIntent, record.Content)
	if cached, ok := f.cache.Get(cacheKey); ok {
		cached.LatencyMs = float64(time.Since(start).Microseconds()) / 1000.0
		return cached
	}

	// Tier 0: Normalization (NFKC + invisible/tag rune recovery + comment unwrap + nested Base64/Hex decode)
	normRes := Normalize(record.Content)

	// Tier 1: OWASP LLM01 Static Signature & Cloaked Payload Detection
	det := f.detector.ScanNormalized(record.Content, normRes)

	// Tier 2: Pre-Flight Sanitization (WebSocket / Localhost pivot / Iterative Delimiter Strip)
	sanRes := f.sanitizer.Sanitize(normRes.Cleaned)

	// Post-sanitize re-scan: ensure delimiter neutralization did not expose a secondary injection
	postDet := f.detector.Scan(sanRes.Cleaned)

	// Merge matched rules & details deterministically
	ruleSet := make(map[string]struct{}, len(det.MatchedRuleIDs)+len(postDet.MatchedRuleIDs)+2)
	var matchedRules []string
	var details []string
	addRule := func(id, detail string) {
		if _, exists := ruleSet[id]; !exists {
			ruleSet[id] = struct{}{}
			matchedRules = append(matchedRules, id)
		}
		if detail != "" {
			details = append(details, detail)
		}
	}

	for _, id := range det.MatchedRuleIDs {
		addRule(id, "")
	}
	details = append(details, det.Details...)
	for _, id := range postDet.MatchedRuleIDs {
		addRule(id, "")
	}
	for _, d := range postDet.Details {
		details = append(details, "post_sanitize:"+d)
	}

	riskScore := det.Confidence
	if postDet.Confidence > riskScore {
		riskScore = postDet.Confidence
	}

	// Tier 3: Semantic Intent-Drift Scoring (applied to non-local tainted context)
	var drift *IntentDriftScore
	if effectiveTaint != TRUST_LOCAL_WORKSPACE {
		drift = AnalyzeIntentDrift(record.TaskIntent, normRes.Cleaned)
		if drift.DriftDetected {
			addRule("DRIFT-001", drift.Reason)
			if drift.ImperativeScore > riskScore {
				riskScore = drift.ImperativeScore
			}
		}
	}

	verdict := &Verdict{
		Taint:          effectiveTaint,
		CleanedContent: normRes.Cleaned,
		RiskScore:      riskScore,
		MatchedRules:   matchedRules,
		Details:        details,
	}

	switch {
	case det.IsInjected || postDet.IsInjected:
		verdict.Status = DecisionQuarantined
		verdict.Reason = det.Reason
		if verdict.Reason == "" {
			verdict.Reason = postDet.Reason
		}
		if sanRes.TotalNeutralized > 0 {
			verdict.CleanedContent = sanRes.Cleaned
		}

	case drift != nil && drift.DriftDetected:
		verdict.Status = DecisionQuarantined
		verdict.Reason = drift.Reason
		if sanRes.TotalNeutralized > 0 {
			verdict.CleanedContent = sanRes.Cleaned
		}

	case (sanRes.WebSocketNeutralized > 0 || sanRes.LocalhostNeutralized > 0) &&
		effectiveTaint != TRUST_LOCAL_WORKSPACE && targetPrivilege == PRIVILEGE_HIGH:
		addRule("PIVOT-001", fmt.Sprintf("untrusted pivot neutralized (ws=%d localhost=%d)", sanRes.WebSocketNeutralized, sanRes.LocalhostNeutralized))
		verdict.MatchedRules = matchedRules
		verdict.Details = details
		if verdict.RiskScore < 0.85 {
			verdict.RiskScore = 0.85
		}
		verdict.Status = DecisionQuarantined
		verdict.Reason = "untrusted WebSocket or localhost control pivot blocked fail-closed"
		verdict.CleanedContent = sanRes.Cleaned

	case sanRes.TotalNeutralized > 0 || normRes.StrippedRunes > 0 || len(normRes.MarkersFound) > 0:
		verdict.Status = DecisionSanitized
		verdict.CleanedContent = sanRes.Cleaned
		if sanRes.TotalNeutralized == 0 {
			verdict.CleanedContent = normRes.Cleaned
		}
		var reasons []string
		if normRes.StrippedRunes > 0 {
			reasons = append(reasons, fmt.Sprintf("stripped %d invisible/format runes", normRes.StrippedRunes))
		}
		if sanRes.TotalNeutralized > 0 {
			reasons = append(reasons, fmt.Sprintf("neutralized %d pre-flight hazards", sanRes.TotalNeutralized))
		}
		if len(normRes.MarkersFound) > 0 {
			reasons = append(reasons, fmt.Sprintf("flattened %d instruction markers", len(normRes.MarkersFound)))
		}
		verdict.Reason = strings.Join(reasons, "; ")
		if verdict.RiskScore < 0.15 {
			verdict.RiskScore = 0.15
		}

	default:
		verdict.Status = DecisionAllowed
	}

	verdict.LatencyMs = float64(time.Since(start).Microseconds()) / 1000.0
	f.cache.Set(cacheKey, verdict)
	return cloneVerdict(verdict)
}
