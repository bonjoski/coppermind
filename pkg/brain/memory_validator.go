package brain

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/bonjoski/coppermind/pkg/authz"
	"github.com/bonjoski/coppermind/pkg/security"
)

var (
	// ErrInvalidAuthorSignature is returned when cryptographic attribution verification fails.
	ErrInvalidAuthorSignature = errors.New("memory validator: invalid author cryptographic signature")
	// ErrScratchpadIntegrityFail is returned when memory validation discovers unrecoverable tampering.
	ErrScratchpadIntegrityFail = errors.New("memory validator: episodic scratchpad integrity check failed")
)

// ValidationVerdict represents the outcome of memory and scratchpad validation.
type ValidationVerdict struct {
	CleanedContent    string   `json:"cleaned_content"`
	TaintScore        float64  `json:"taint_score"`
	Flags             []string `json:"flags,omitempty"`
	SignatureVerified bool     `json:"signature_verified"`
	Quarantined       bool     `json:"quarantined"`
	QuarantineReason  string   `json:"quarantine_reason,omitempty"`
	RedactedCount     int      `json:"redacted_count"`
}

// MemoryValidator enforces episodic scratchpad integrity, author attribution, and partition quarantine.
type MemoryValidator struct{}

// NewMemoryValidator creates a new MemoryValidator.
func NewMemoryValidator() *MemoryValidator {
	return &MemoryValidator{}
}

// Validate verifies the integrity of an incoming memory request before embedding and storage.
// Enforces:
// 1. Author attribution cryptographic signature (Ed25519) when present.
// 2. Content sanitization stripping indirect prompt injections and XML tool reflection tags.
// 3. Quarantining untrusted external observations to a separate `quarantined_observations` partition.
func (v *MemoryValidator) Validate(_ context.Context, req *RememberRequest) (*ValidationVerdict, error) {
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

	// 2. Secret & Credential Sanitization
	secRes, err := security.SanitizeMemory(req.Content)
	if err != nil {
		return nil, fmt.Errorf("memory content rejected by secret policy: %w", err)
	}
	verdict.RedactedCount = secRes.RedactedCount

	// 3. XML Tool Reflection & Artificial Delimiter Defanging
	strippedXML, defangedCount := security.SanitizeXMLDelimiters(secRes.SanitizedText)
	if defangedCount > 0 {
		verdict.Flags = append(verdict.Flags, fmt.Sprintf("defanged_%d_xml_delimiters", defangedCount))
	}

	// 4. Cognitive Threat Inspection (Prompt Injection & Jailbreak Defense)
	threatRes, err := security.InspectCognitiveThreats(strippedXML)
	if err != nil {
		return nil, fmt.Errorf("cognitive threat inspection failed: %w", err)
	}
	verdict.TaintScore = threatRes.TaintScore
	verdict.Flags = append(verdict.Flags, threatRes.Flags...)

	// Fail-closed invariant: critical prompt injection from untrusted provenance is rejected immediately
	if threatRes.IsCritical && req.Provenance != ProvenanceLocalWorkspace {
		return nil, fmt.Errorf("untrusted input rejected: %w", security.ErrPromptInjectionRejected)
	}

	// 5. Partitioning & Quarantining Rules
	// If observation is from untrusted external sources, or has elevated taint/threats:
	// Automatically isolate it into the `quarantined_observations` partition.
	needsQuarantine := false
	var quarantineReasons []string

	if threatRes.TaintScore >= 0.5 {
		needsQuarantine = true
		quarantineReasons = append(quarantineReasons, fmt.Sprintf("high_taint_score:%.2f", threatRes.TaintScore))
	}
	if threatRes.IsCritical && req.Provenance == ProvenanceLocalWorkspace {
		// Local workspace with critical threat is retained for analysis in quarantined_observations partition
		needsQuarantine = true
		quarantineReasons = append(quarantineReasons, "local_critical_threat_quarantined")
	}
	if (req.Category == "observation" || req.Category == "" || req.Derived) && req.Provenance != ProvenanceLocalWorkspace {
		// Untrusted external observations are quarantined to prevent unvetted cognitive drift
		needsQuarantine = true
		quarantineReasons = append(quarantineReasons, fmt.Sprintf("untrusted_observation_provenance:%s", req.Provenance))
	}
	if req.Metadata != nil && req.Metadata["quarantined"] == "true" {
		needsQuarantine = true
		quarantineReasons = append(quarantineReasons, "metadata_quarantined_flag")
	}

	if needsQuarantine {
		verdict.Quarantined = true
		verdict.QuarantineReason = strings.Join(quarantineReasons, "; ")

		// Partitioning: route to quarantined_observations and demote lifecycle authority
		req.Category = "quarantined_observations"
		req.LifecycleStatus = string(authz.StatusProposed)
		req.AuthorityTier = authz.TierName4Scratchpad
		req.Derived = true

		if req.Metadata == nil {
			req.Metadata = make(map[string]string)
		}
		req.Metadata["quarantined"] = "true"
		req.Metadata["quarantine_reason"] = verdict.QuarantineReason
	}

	verdict.CleanedContent = strippedXML
	return verdict, nil
}
