package brain

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/bonjoski/coppermind/pkg/authz"
	"github.com/bonjoski/coppermind/pkg/memguard"
	"github.com/bonjoski/coppermind/pkg/security"
)

var (
	// ErrInvalidAuthorSignature is returned when cryptographic attribution verification fails.
	ErrInvalidAuthorSignature = errors.New("memory validator: invalid author cryptographic signature")
	// ErrScratchpadIntegrityFail is returned when memory validation discovers unrecoverable tampering.
	ErrScratchpadIntegrityFail = errors.New("memory validator: episodic scratchpad integrity check failed")
)

// ValidationVerdict represents the outcome of memory, git-diff, and scratchpad validation.
type ValidationVerdict struct {
	CleanedContent    string   `json:"cleaned_content"`
	TaintScore        float64  `json:"taint_score"`
	Flags             []string `json:"flags,omitempty"`
	SignatureVerified bool     `json:"signature_verified"`
	Quarantined       bool     `json:"quarantined"`
	QuarantineReason  string   `json:"quarantine_reason,omitempty"`
	RedactedCount     int      `json:"redacted_count"`

	// Embedded Stormcage semantic taint & integrity telemetry (RFC-2026-11-24-54)
	StormcageDecision string   `json:"stormcage_decision,omitempty"`
	EffectiveTaint    string   `json:"effective_taint,omitempty"`
	MatchedRules      []string `json:"matched_rules,omitempty"`
	StrippedRunes     int      `json:"stripped_runes,omitempty"`
	DecodedPayloads   int      `json:"decoded_payloads,omitempty"`
	IntegrityDigest   string   `json:"integrity_digest,omitempty"`
}

// MemoryValidator enforces episodic scratchpad integrity, in-process cognitive memory
// firewall & semantic taint tracking, author attribution, and partition quarantine with
// zero external daemon hop tax or private repository dependencies.
type MemoryValidator struct {
	firewall  *memguard.Firewall
	sanitizer *memguard.PreFlightSanitizer
	ledger    *memguard.TaintLedger
}

// NewMemoryValidator creates a new MemoryValidator backed by the built-in in-process memguard engine.
func NewMemoryValidator() *MemoryValidator {
	return &MemoryValidator{
		firewall:  memguard.NewFirewall(),
		sanitizer: memguard.NewPreFlightSanitizer(),
		ledger:    memguard.NewTaintLedger(),
	}
}

func (v *MemoryValidator) ensureEngines() {
	if v.firewall == nil {
		v.firewall = memguard.NewFirewall()
	}
	if v.sanitizer == nil {
		v.sanitizer = memguard.NewPreFlightSanitizer()
	}
	if v.ledger == nil {
		v.ledger = memguard.NewTaintLedger()
	}
}

// TaintLedger returns the in-process session-partitioned memguard TaintLedger.
func (v *MemoryValidator) TaintLedger() *memguard.TaintLedger {
	v.ensureEngines()
	return v.ledger
}

// ComputeIntegrityDigest computes a canonical SHA-256 digest binding provenance taint and sanitized content.
func ComputeIntegrityDigest(effectiveTaint, cleanedContent string) string {
	h := sha256.New()
	h.Write([]byte("coppermind-stormcage-v1:"))
	h.Write([]byte(effectiveTaint))
	h.Write([]byte{0})
	h.Write([]byte(cleanedContent))
	return hex.EncodeToString(h.Sum(nil))
}

func resolveEffectiveTaint(req *RememberRequest) memguard.TaintLevel {
	base := req.Provenance.ToTaintLevel()
	if req.Provenance == "" {
		base = memguard.TRUST_LOCAL_WORKSPACE
	}

	// Prevent provenance spoofing on third-party/unsigned git diffs and shared history
	isDiffOrUnsigned := strings.EqualFold(req.Category, "git_diff")
	if req.Metadata != nil {
		if strings.EqualFold(req.Metadata["source"], "git_diff") ||
			strings.EqualFold(req.Metadata["git_third_party"], "true") ||
			strings.EqualFold(req.Metadata["git_signed"], "false") {
			isDiffOrUnsigned = true
		}
	}
	if isDiffOrUnsigned {
		base = memguard.MergeTaints(base, memguard.TAINT_SHARED_DOC)
	}
	return base
}

func sanitizeAgentID(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "coppermind-local"
	}
	var sb strings.Builder
	for _, r := range raw {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
			sb.WriteRune(r)
		} else {
			sb.WriteByte('_')
		}
		if sb.Len() >= 64 {
			break
		}
	}
	if sb.Len() == 0 {
		return "coppermind-local"
	}
	return sb.String()
}

// Validate verifies the integrity of an incoming memory request before embedding and SQLite WAL storage.
// Enforces:
// 1. Author attribution cryptographic signature (Ed25519) when present.
// 2. Secret & credential quarantine.
// 3. Embedded Stormcage semantic taint tracking, NFKC/Unicode-Tag/Base64 normalization, and multi-tier firewall gating.
// 4. XML tool reflection & artificial delimiter defanging + defense-in-depth cognitive inspection.
// 5. Partitioning untrusted external/shared-doc observations to `quarantined_observations`.
func (v *MemoryValidator) Validate(_ context.Context, req *RememberRequest) (*ValidationVerdict, error) {
	if req == nil {
		return nil, fmt.Errorf("%w: nil remember request", ErrScratchpadIntegrityFail)
	}
	v.ensureEngines()

	verdict := &ValidationVerdict{
		CleanedContent: req.Content,
	}

	// 1. Author Attribution Cryptographic Signature Check (if provided in metadata)
	if req.Metadata != nil {
		if sigHex, hasSig := req.Metadata["author_signature"]; hasSig && sigHex != "" {
			pubHex, hasPub := req.Metadata["author_pubkey"]
			if !hasPub || pubHex == "" {
				return nil, fmt.Errorf("%w: missing author_pubkey for signature verification", ErrInvalidAuthorSignature)
			}
			sigBytes, err := hex.DecodeString(sigHex)
			if err != nil || len(sigBytes) != ed25519.SignatureSize {
				return nil, fmt.Errorf("%w: malformed signature bytes", ErrInvalidAuthorSignature)
			}
			pubBytes, err := hex.DecodeString(pubHex)
			if err != nil || len(pubBytes) != ed25519.PublicKeySize {
				return nil, fmt.Errorf("%w: malformed public key bytes", ErrInvalidAuthorSignature)
			}
			// Verify signature over payload: authorIdentity + ":" + content
			msgPayload := []byte(req.AuthorIdentity + ":" + req.Content)
			if !ed25519.Verify(pubBytes, msgPayload, sigBytes) {
				return nil, fmt.Errorf("%w: ed25519 signature mismatch", ErrInvalidAuthorSignature)
			}
			verdict.SignatureVerified = true
		}
	}

	// 2. Embedded Stormcage Semantic Taint & Multi-Tier Firewall Gate (in-process, zero WAN)
	// MUST run BEFORE secret redaction / NFKC stripping so Stormcage recovers U+E0000 Unicode tags
	// and Base64/Hex/HTML-comment cloaked prompt injections before high-entropy redaction masks them.
	effectiveTaint := resolveEffectiveTaint(req)
	verdict.EffectiveTaint = string(effectiveTaint)

	// Escalate request provenance if taint propagation elevated it (e.g. unsigned git diff)
	if effectiveTaint != memguard.TRUST_LOCAL_WORKSPACE && req.Provenance == ProvenanceLocalWorkspace {
		req.Provenance = ProvenanceTier(effectiveTaint)
	}

	normRes := memguard.Normalize(req.Content)
	verdict.StrippedRunes = normRes.StrippedRunes
	verdict.DecodedPayloads = len(normRes.DecodedPayloads)

	taskIntent := req.Category
	if req.Metadata != nil && req.Metadata["task_intent"] != "" {
		taskIntent = req.Metadata["task_intent"]
	}
	guardRec := &memguard.MemoryRecord{
		AgentID:    sanitizeAgentID(req.AuthorIdentity),
		Taint:      effectiveTaint,
		Content:    req.Content,
		TaskIntent: taskIntent,
		Metadata:   req.Metadata,
	}
	guardVerdict := v.firewall.Gate(guardRec, memguard.PRIVILEGE_HIGH)
	verdict.StormcageDecision = string(guardVerdict.Status)
	verdict.MatchedRules = append(verdict.MatchedRules, guardVerdict.MatchedRules...)

	if guardVerdict.RiskScore > verdict.TaintScore {
		verdict.TaintScore = guardVerdict.RiskScore
	}
	for _, rID := range guardVerdict.MatchedRules {
		verdict.Flags = append(verdict.Flags, "memguard:"+rID)
	}
	if normRes.StrippedRunes > 0 {
		verdict.Flags = append(verdict.Flags, fmt.Sprintf("memguard_stripped_%d_invisible_runes", normRes.StrippedRunes))
	}
	if len(normRes.DecodedPayloads) > 0 {
		verdict.Flags = append(verdict.Flags, fmt.Sprintf("memguard_decoded_%d_cloaked_payloads", len(normRes.DecodedPayloads)))
	}

	// 3. Secret & Credential Sanitization (runs after cloaking recovery; fails closed on raw private keys)
	secRes, err := security.SanitizeMemory(req.Content)
	if err != nil {
		return nil, fmt.Errorf("memory content rejected by secret policy: %w", err)
	}
	verdict.RedactedCount = secRes.RedactedCount

	// 4. XML Tool Reflection & Artificial Delimiter Defanging
	candidateText := secRes.SanitizedText
	if guardVerdict.Status == memguard.DecisionSanitized && guardVerdict.CleanedContent != "" {
		// Re-run secret sanitization on cleaned text to preserve any credential redactions
		if cleanedSec, secErr := security.SanitizeMemory(guardVerdict.CleanedContent); secErr == nil {
			candidateText = cleanedSec.SanitizedText
		}
	}
	// Neutralize any remaining artificial delimiters or ws/localhost pivots if flagged cloaking or non-local taint
	isTrustedLensFinding := req.Derived && req.SourceLens != "" && effectiveTaint == memguard.TRUST_LOCAL_WORKSPACE
	if !isTrustedLensFinding && (effectiveTaint != memguard.TRUST_LOCAL_WORKSPACE || guardVerdict.Status == memguard.DecisionQuarantined) {
		sanRes := v.sanitizer.Sanitize(candidateText)
		if sanRes.TotalNeutralized > 0 {
			candidateText = sanRes.Cleaned
			verdict.Flags = append(verdict.Flags, fmt.Sprintf("memguard_neutralized_%d_hazards", sanRes.TotalNeutralized))
		}
	}

	strippedXML, defangedCount := security.SanitizeXMLDelimiters(candidateText)
	if defangedCount > 0 {
		verdict.Flags = append(verdict.Flags, fmt.Sprintf("defanged_%d_xml_delimiters", defangedCount))
	}

	// 5. Defense-in-depth Cognitive Threat Inspection
	threatRes, err := security.InspectCognitiveThreats(strippedXML)
	if err != nil {
		return nil, fmt.Errorf("cognitive threat inspection failed: %w", err)
	}
	if threatRes.TaintScore > verdict.TaintScore {
		verdict.TaintScore = threatRes.TaintScore
	}
	verdict.Flags = append(verdict.Flags, threatRes.Flags...)

	isCritical := threatRes.IsCritical || guardVerdict.Status == memguard.DecisionQuarantined

	// Fail-closed invariant: critical prompt injection or firewall quarantine from any non-local provenance is rejected immediately
	if isCritical && effectiveTaint != memguard.TRUST_LOCAL_WORKSPACE {
		return nil, fmt.Errorf(
			"untrusted input rejected (taint=%s memguard=%s rules=%s): %w",
			effectiveTaint,
			guardVerdict.Status,
			strings.Join(verdict.MatchedRules, ","),
			security.ErrPromptInjectionRejected,
		)
	}

	// 6. Partitioning & Quarantining Rules
	needsQuarantine := false
	var quarantineReasons []string

	// Trusted local cognitive lens findings are already isolated as Derived=true / TIER_3_DERIVED
	// and frequently quote security PoC snippets (e.g. bash -c / localhost); preserve their lens tier.
	if !isTrustedLensFinding {
		if verdict.TaintScore >= 0.5 {
			needsQuarantine = true
			quarantineReasons = append(quarantineReasons, fmt.Sprintf("high_taint_score:%.2f", verdict.TaintScore))
		}
		if isCritical && effectiveTaint == memguard.TRUST_LOCAL_WORKSPACE {
			needsQuarantine = true
			quarantineReasons = append(quarantineReasons, "local_critical_threat_quarantined")
		}
		if (req.Category == "observation" || req.Category == "git_diff" || req.Category == "" || req.Derived) &&
			effectiveTaint != memguard.TRUST_LOCAL_WORKSPACE {
			needsQuarantine = true
			quarantineReasons = append(quarantineReasons, fmt.Sprintf("untrusted_observation_provenance:%s", effectiveTaint))
		}
		if (normRes.StrippedRunes > 0 || len(normRes.DecodedPayloads) > 0) && effectiveTaint != memguard.TRUST_LOCAL_WORKSPACE {
			needsQuarantine = true
			quarantineReasons = append(quarantineReasons, "memguard_cloaked_content_detected")
		}
		if req.Metadata != nil && req.Metadata["quarantined"] == "true" {
			needsQuarantine = true
			quarantineReasons = append(quarantineReasons, "metadata_quarantined_flag")
		}
	}

	verdict.CleanedContent = strippedXML
	verdict.IntegrityDigest = ComputeIntegrityDigest(string(effectiveTaint), strippedXML)

	if req.Metadata == nil {
		req.Metadata = make(map[string]string)
	}
	req.Metadata["stormcage_decision"] = verdict.StormcageDecision
	req.Metadata["stormcage_taint"] = verdict.EffectiveTaint
	req.Metadata["integrity_digest"] = verdict.IntegrityDigest
	if len(verdict.MatchedRules) > 0 {
		req.Metadata["stormcage_rules"] = strings.Join(verdict.MatchedRules, ",")
	}

	if needsQuarantine {
		verdict.Quarantined = true
		verdict.QuarantineReason = strings.Join(quarantineReasons, "; ")

		// Partitioning: route to quarantined_observations and demote lifecycle authority
		req.Category = "quarantined_observations"
		req.LifecycleStatus = string(authz.StatusProposed)
		req.AuthorityTier = authz.TierName4Scratchpad
		req.Derived = true

		req.Metadata["quarantined"] = "true"
		req.Metadata["quarantine_reason"] = verdict.QuarantineReason
	}

	return verdict, nil
}

// ValidateScratchpadWrite validates and sanitizes a working-memory scratchpad entry using the
// embedded Stormcage engine. Fails closed on any prompt injection, cloaked Unicode/Base64 payload,
// localhost/WebSocket pivot, or secret private key leak before the value touches memory or Redis.
func (v *MemoryValidator) ValidateScratchpadWrite(
	_ context.Context,
	sessionID, key, value string,
	provenance ProvenanceTier,
) (*ValidationVerdict, error) {
	v.ensureEngines()

	if provenance == "" {
		provenance = ProvenanceSharedDoc
	}
	effectiveTaint := provenance.ToTaintLevel()

	// Run memguard normalization & firewall BEFORE secret redaction so U+E0000 Unicode tags
	// and Base64-cloaked injections are recovered and blocked instead of masked.
	normRes := memguard.Normalize(value)
	guardRec := &memguard.MemoryRecord{
		AgentID:    sanitizeAgentID(sessionID),
		Taint:      effectiveTaint,
		Content:    value,
		TaskIntent: "scratchpad:" + key,
	}
	guardVerdict := v.firewall.Gate(guardRec, memguard.PRIVILEGE_HIGH)

	if guardVerdict.Status == memguard.DecisionQuarantined {
		return nil, fmt.Errorf(
			"scratchpad write rejected for key %q (memguard=%s rules=%s): %w",
			key,
			guardVerdict.Status,
			strings.Join(guardVerdict.MatchedRules, ","),
			security.ErrPromptInjectionRejected,
		)
	}

	candidate := value
	if guardVerdict.Status == memguard.DecisionSanitized && guardVerdict.CleanedContent != "" {
		candidate = guardVerdict.CleanedContent
	}

	secRes, err := security.SanitizeMemory(candidate)
	if err != nil {
		return nil, fmt.Errorf("scratchpad write rejected for key %q: %w", key, err)
	}

	cleaned, defanged := security.SanitizeXMLDelimiters(secRes.SanitizedText)

	threatRes, err := security.InspectCognitiveThreats(cleaned)
	if err != nil {
		return nil, fmt.Errorf("scratchpad cognitive inspection failed: %w", err)
	}
	if threatRes.IsCritical {
		return nil, fmt.Errorf(
			"scratchpad write rejected for key %q (%s): %w",
			key,
			strings.Join(threatRes.Flags, ", "),
			security.ErrPromptInjectionRejected,
		)
	}

	taintScore := threatRes.TaintScore
	if guardVerdict.RiskScore > taintScore {
		taintScore = guardVerdict.RiskScore
	}

	flags := append([]string(nil), threatRes.Flags...)
	if defanged > 0 {
		flags = append(flags, fmt.Sprintf("defanged_%d_xml_delimiters", defanged))
	}
	if normRes.StrippedRunes > 0 {
		flags = append(flags, fmt.Sprintf("memguard_stripped_%d_invisible_runes", normRes.StrippedRunes))
	}

	return &ValidationVerdict{
		CleanedContent:    cleaned,
		TaintScore:        taintScore,
		Flags:             flags,
		RedactedCount:     secRes.RedactedCount,
		StormcageDecision: string(guardVerdict.Status),
		EffectiveTaint:    string(effectiveTaint),
		MatchedRules:      guardVerdict.MatchedRules,
		StrippedRunes:     normRes.StrippedRunes,
		DecodedPayloads:   len(normRes.DecodedPayloads),
		IntegrityDigest:   ComputeIntegrityDigest(string(effectiveTaint), cleaned),
	}, nil
}

// VerifyGitDiff inspects an incoming git diff (e.g., from post-commit, post-merge, or a third-party PR)
// using the built-in memguard engine to catch poisoned comments, invisible Unicode tag smuggling,
// Base64/Hex encoded prompt injections, XML tool reflection, and imperative drift before the diff
// enters episodic memory or agent scratchpads.
func (v *MemoryValidator) VerifyGitDiff(
	ctx context.Context,
	sessionID, diffContent, author string,
	signed bool,
	repoName, commitHash string,
) (*ValidationVerdict, error) {
	v.ensureEngines()

	if strings.TrimSpace(diffContent) == "" {
		return &ValidationVerdict{
			CleanedContent:    "",
			StormcageDecision: string(memguard.DecisionAllowed),
			EffectiveTaint:    string(memguard.TRUST_LOCAL_WORKSPACE),
			IntegrityDigest:   ComputeIntegrityDigest(string(memguard.TRUST_LOCAL_WORKSPACE), ""),
		}, nil
	}

	provenance := ProvenanceSharedDoc
	if signed {
		// Even signed commits inspect added diff lines against Tier 0 cloaking/injection rules,
		// because a signed merge commit can pull in a poisoned third-party dependency or PR diff.
		provenance = ProvenanceSharedDoc
	}

	// Extract added lines ('+' lines excluding '+++') so diff context markers don't obscure injections
	var addedLines strings.Builder
	for _, line := range strings.Split(diffContent, "\n") {
		if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
			addedLines.WriteString(strings.TrimPrefix(line, "+"))
			addedLines.WriteByte('\n')
		}
	}
	inspectPayload := addedLines.String()
	if strings.TrimSpace(inspectPayload) == "" {
		inspectPayload = diffContent
	}

	req := &RememberRequest{
		SessionID:      sessionID,
		Category:       "git_diff",
		Content:        inspectPayload,
		Provenance:     provenance,
		AuthorIdentity: author,
		Metadata: map[string]string{
			"source":          "git_diff",
			"git_repo":        repoName,
			"git_commit":      commitHash,
			"git_signed":      fmt.Sprintf("%t", signed),
			"git_third_party": fmt.Sprintf("%t", !signed),
		},
	}

	return v.Validate(ctx, req)
}

// ValidateNodeForStorage is an in-process SQLite WAL pre-write verification hook.
// It guarantees that even direct MemoryStore.Store callers bypassing brain.Manager.Remember
// cannot persist unvalidated poisoned context into the SQLite WAL database.
// Nodes already validated by Manager.Remember hit the fast-path integrity digest check (<5µs).
func (v *MemoryValidator) ValidateNodeForStorage(ctx context.Context, node *MemoryNode) error {
	if node == nil {
		return fmt.Errorf("%w: nil memory node", ErrScratchpadIntegrityFail)
	}
	v.ensureEngines()

	// Fast path: already verified by MemoryValidator.Validate and content matches integrity digest
	if node.Metadata != nil {
		if digest := node.Metadata["integrity_digest"]; digest != "" {
			taintStr := node.Metadata["stormcage_taint"]
			if taintStr == "" {
				taintStr = string(node.Provenance.ToStormcageTaint())
			}
			if digest == ComputeIntegrityDigest(taintStr, node.Content) {
				return nil
			}
		}
	}

	// Slow path: direct store write bypassing Manager.Remember — enforce full Stormcage gate
	prov := node.Provenance
	if prov == "" {
		prov = ProvenanceSharedDoc
	}
	req := &RememberRequest{
		SessionID:       node.SessionID,
		Category:        node.Category,
		Content:         node.Content,
		Provenance:      prov,
		Metadata:        node.Metadata,
		Derived:         node.Derived,
		AuthorityTier:   node.AuthorityTier,
		LifecycleStatus: node.LifecycleStatus,
		AuthorIdentity:  node.AuthorIdentity,
		AuthorRole:      node.AuthorRole,
	}

	verdict, err := v.Validate(ctx, req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrScratchpadIntegrityFail, err)
	}

	node.Content = verdict.CleanedContent
	node.TaintScore = verdict.TaintScore
	node.Provenance = req.Provenance
	node.Category = req.Category
	node.LifecycleStatus = req.LifecycleStatus
	node.AuthorityTier = req.AuthorityTier
	node.Derived = req.Derived
	node.Metadata = req.Metadata
	return nil
}
