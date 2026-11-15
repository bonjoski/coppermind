package authz

import (
	"context"
	"strings"
)

// DefaultPolicyEnforcer implements PolicyEnforcer with role-based and capability-based authorization.
type DefaultPolicyEnforcer struct {
	AllowProposals       bool
	MaxSupersessionDepth int
}

// NewDefaultPolicyEnforcer creates a new policy enforcer with default settings.
func NewDefaultPolicyEnforcer() *DefaultPolicyEnforcer {
	return &DefaultPolicyEnforcer{
		AllowProposals:       true,
		MaxSupersessionDepth: 16,
	}
}

// AuthorizeWrite evaluates the caller's credentials against the requested tier and category.
func (e *DefaultPolicyEnforcer) AuthorizeWrite(ctx context.Context, claims SubjectClaims, req MemoryWriteRequest) (AuthorityTier, LifecycleStatus, error) {
	tier := req.RequestedTier
	if tier == TierUnspecified {
		tier = CategoryToDefaultTier(req.Category)
	}

	role := strings.ToLower(strings.TrimSpace(claims.Role))

	switch tier {
	case Tier0Sovereign:
		// Sovereign Invariants require security officer or root cryptographic delegation
		if role == "security-officer" || role == "root" || claims.HasScope("memory:root:write") || claims.HasScope("memory:sovereign:write") {
			return Tier0Sovereign, StatusActive, nil
		}
		// Tier 0 cannot be proposed interactively; must fail closed
		return Tier0Sovereign, StatusRejected, ErrForbiddenAuthority

	case Tier1Architecture:
		// Architecture decisions require architect or tech-lead roles or explicit scope
		if role == "architect" || role == "tech-lead" || claims.HasScope("memory:architecture:write") {
			return Tier1Architecture, StatusActive, nil
		}
		if e.AllowProposals {
			return Tier1Architecture, StatusProposed, ErrForbiddenAuthority
		}
		return Tier1Architecture, StatusRejected, ErrForbiddenAuthority

	case Tier2Product:
		// Product specifications require product owner or manager roles or explicit scope
		if role == "product_owner" || role == "product_manager" || role == "product-owner" || claims.HasScope("memory:product:write") {
			return Tier2Product, StatusActive, nil
		}
		if e.AllowProposals {
			return Tier2Product, StatusProposed, ErrForbiddenAuthority
		}
		return Tier2Product, StatusRejected, ErrForbiddenAuthority

	case Tier3Episodic:
		// Episodic logs and commit history are writeable by developers, agents, and CI pipelines
		return Tier3Episodic, StatusActive, nil

	case Tier4Scratchpad:
		// Working scratchpad memory is writeable by any active agent session
		return Tier4Scratchpad, StatusActive, nil

	default:
		return Tier3Episodic, StatusActive, nil
	}
}

// ValidateSupersession verifies that the caller has sufficient authority to supersede targetNode,
// and ensures the supersession does not create cycles in the memory DAG.
func (e *DefaultPolicyEnforcer) ValidateSupersession(
	ctx context.Context,
	claims SubjectClaims,
	targetTier AuthorityTier,
	targetID, supersedingID string,
	getAncestors func(id string) ([]string, error),
) error {
	role := strings.ToLower(strings.TrimSpace(claims.Role))

	// Domain-specific authority boundary checks
	switch targetTier {
	case Tier0Sovereign:
		if role != "security-officer" && role != "root" && !claims.HasScope("memory:root:write") && !claims.HasScope("memory:sovereign:write") {
			return ErrForbiddenAuthority
		}

	case Tier1Architecture:
		// Product owners or general agents cannot supersede architecture invariants
		if role != "architect" && role != "tech-lead" && !claims.HasScope("memory:architecture:write") {
			return ErrForbiddenAuthority
		}

	case Tier2Product:
		// Architects or general developers cannot unilaterally supersede product specifications without product scope
		if role != "product_owner" && role != "product_manager" && role != "product-owner" && !claims.HasScope("memory:product:write") {
			return ErrForbiddenAuthority
		}
	}

	// Cycle detection in the DAG
	if supersedingID != "" && targetID != "" && supersedingID == targetID {
		return ErrCyclicSupersession
	}

	if getAncestors != nil && supersedingID != "" && targetID != "" {
		ancestors, err := getAncestors(targetID)
		if err != nil {
			return err
		}
		maxDepth := e.MaxSupersessionDepth
		if maxDepth <= 0 {
			maxDepth = 16
		}
		depth := 0
		visited := make(map[string]bool)
		for len(ancestors) > 0 {
			if depth > maxDepth {
				return ErrCyclicSupersession
			}
			depth++

			current := ancestors[0]
			ancestors = ancestors[1:]

			if current == supersedingID {
				return ErrCyclicSupersession
			}
			if visited[current] {
				continue
			}
			visited[current] = true

			nextGen, err := getAncestors(current)
			if err != nil {
				return err
			}
			ancestors = append(ancestors, nextGen...)
		}
	}

	return nil
}
