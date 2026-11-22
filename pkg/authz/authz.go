package authz

import (
	"context"
	"errors"
	"strings"
)

var (
	ErrForbiddenAuthority     = errors.New("authz: caller role lacks required epistemic authority tier")
	ErrInvalidSupersession    = errors.New("authz: cannot supersede a memory of higher authority tier")
	ErrDirectMutationBlocked = errors.New("authz: immutable ledger: memories must be superseded, not mutated")
	ErrCyclicSupersession     = errors.New("authz: cyclic supersession detected in graph lineage")
	ErrMissingRationale       = errors.New("authz: rationale is required when superseding an existing memory")
)

// AuthorityTier represents the epistemic weight and privilege tier of a memory.
type AuthorityTier int

const (
	TierUnspecified    AuthorityTier = 0
	Tier4Scratchpad    AuthorityTier = 10
	Tier3Episodic      AuthorityTier = 50
	Tier2MentorCapsule AuthorityTier = 60
	Tier2Product       AuthorityTier = 70
	Tier1Architecture  AuthorityTier = 80
	Tier0Sovereign     AuthorityTier = 100
)

const (
	TierName0Sovereign     = "TIER_0_SOVEREIGN"
	TierName1Architecture  = "TIER_1_ARCHITECTURE"
	TierName2Product       = "TIER_2_PRODUCT"
	TierName2MentorCapsule = "TIER_2_MENTOR_CAPSULE"
	TierName3Episodic      = "TIER_3_EPISODIC"
	TierName4Scratchpad    = "TIER_4_SCRATCHPAD"
)

// LifecycleStatus defines the state of a memory in the active consensus.
type LifecycleStatus string

const (
	StatusActive     LifecycleStatus = "ACTIVE"
	StatusSuperseded LifecycleStatus = "SUPERSEDED"
	StatusProposed   LifecycleStatus = "PROPOSED"
	StatusRejected   LifecycleStatus = "REJECTED"
	StatusDeprecated LifecycleStatus = "DEPRECATED"
)

// ParseAuthorityTier converts string representation to AuthorityTier.
func ParseAuthorityTier(name string) AuthorityTier {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case TierName0Sovereign, "TIER_0", "SOVEREIGN":
		return Tier0Sovereign
	case TierName1Architecture, "TIER_1", "ARCHITECTURE", "ARCH":
		return Tier1Architecture
	case TierName2Product, "TIER_2", "PRODUCT":
		return Tier2Product
	case TierName2MentorCapsule, "MENTOR_CAPSULE", "MENTOR":
		return Tier2MentorCapsule
	case TierName3Episodic, "TIER_3", "EPISODIC":
		return Tier3Episodic
	case TierName4Scratchpad, "TIER_4", "SCRATCHPAD", "WORKING":
		return Tier4Scratchpad
	default:
		return TierUnspecified
	}
}

// TierToString returns canonical string representation of AuthorityTier.
func TierToString(tier AuthorityTier, category ...string) string {
	switch tier {
	case Tier0Sovereign:
		return TierName0Sovereign
	case Tier1Architecture:
		return TierName1Architecture
	case Tier2Product:
		return TierName2Product
	case Tier2MentorCapsule:
		return TierName2MentorCapsule
	case Tier3Episodic:
		return TierName3Episodic
	case Tier4Scratchpad:
		return TierName4Scratchpad
	default:
		return TierName3Episodic
	}
}

// CategoryToDefaultTier maps memory category to its default authority tier.
func CategoryToDefaultTier(category string) AuthorityTier {
	cat := strings.ToLower(strings.TrimSpace(category))
	switch cat {
	case "security_policy", "sandbox_rule", "crypto_root", "sovereign_invariant":
		return Tier0Sovereign
	case "architecture", "convention", "tech_stack", "api_schema", "decision", "accepted-rfc", "ecosystem-architecture", "rfc", "adr", "learning", "architectural-learning", "lesson", "learnings":
		return Tier1Architecture
	case "product", "user_story", "acceptance_criteria", "spec", "business_logic":
		return Tier2Product
	case "working", "scratchpad", "agent_state", "mutex_lock":
		return Tier4Scratchpad
	default:
		return Tier3Episodic
	}
}

// SubjectClaims encapsulates identity, role, and capabilities extracted from Conjoiner DPoP or OIDC JWT.
type SubjectClaims struct {
	Subject        string   `json:"sub"`
	TenantID       string   `json:"tenant_id"`
	ProjectID      string   `json:"project_id"`
	Role           string   `json:"role"`           // e.g. "security-officer", "architect", "tech-lead", "product_owner", "developer", "subagent"
	Scopes         []string `json:"scopes"`         // e.g. ["memory:architecture:write", "memory:product:write", "memory:read"]
	DPoPThumbprint string   `json:"dpop_jkt,omitempty"`
	SignatureValid bool     `json:"sig_valid"`
}

// HasScope checks if the subject holds a specific authorization scope or a wildcard.
func (c *SubjectClaims) HasScope(scope string) bool {
	for _, s := range c.Scopes {
		if s == scope || s == "*" || s == "memory:*" {
			return true
		}
		if strings.HasSuffix(s, ":*") {
			prefix := strings.TrimSuffix(s, ":*")
			if strings.HasPrefix(scope, prefix) {
				return true
			}
		}
	}
	return false
}

// MemoryWriteRequest represents an inbound request to store or supersede a memory.
type MemoryWriteRequest struct {
	Category      string
	Content       string
	RequestedTier AuthorityTier
	SupersedesID  *string
	Rationale     string
	AdvisoryRef   string
}

// PolicyEnforcer defines the epistemic policy enforcement contract.
type PolicyEnforcer interface {
	// AuthorizeWrite evaluates claims against the write request.
	// Returns the determined authority tier, target lifecycle status, and error.
	AuthorizeWrite(ctx context.Context, claims SubjectClaims, req MemoryWriteRequest) (AuthorityTier, LifecycleStatus, error)

	// ValidateSupersession verifies that the caller can supersede targetNode, checking tier hierarchy and cycle freedom.
	ValidateSupersession(ctx context.Context, claims SubjectClaims, targetTier AuthorityTier, targetID, supersedingID string, getAncestors func(id string) ([]string, error)) error
}
