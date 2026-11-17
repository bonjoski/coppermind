package authz

import (
	"context"
	"errors"
	"testing"
)

func TestAuthorizeWrite_Architect(t *testing.T) {
	enforcer := NewDefaultPolicyEnforcer()
	ctx := context.Background()

	archClaims := SubjectClaims{
		Subject: "alice@corp.org",
		Role:    "architect",
		Scopes:  []string{"memory:architecture:write", "memory:read"},
	}

	req := MemoryWriteRequest{
		Category: "architecture",
		Content:  "Use PostgreSQL 17 with pgvector",
	}

	tier, status, err := enforcer.AuthorizeWrite(ctx, archClaims, req)
	if err != nil {
		t.Fatalf("expected author write to succeed, got %v", err)
	}
	if tier != Tier1Architecture {
		t.Errorf("expected Tier1Architecture, got %v", tier)
	}
	if status != StatusActive {
		t.Errorf("expected StatusActive, got %v", status)
	}
}

func TestAuthorizeWrite_ProductOwner_BlockedFromArchitecture(t *testing.T) {
	enforcer := NewDefaultPolicyEnforcer()
	ctx := context.Background()

	poClaims := SubjectClaims{
		Subject: "bob@corp.org",
		Role:    "product_owner",
		Scopes:  []string{"memory:product:write", "memory:read"},
	}

	req := MemoryWriteRequest{
		Category: "architecture",
		Content:  "Let's switch to MongoDB",
	}

	tier, status, err := enforcer.AuthorizeWrite(ctx, poClaims, req)
	if !errors.Is(err, ErrForbiddenAuthority) {
		t.Fatalf("expected ErrForbiddenAuthority, got %v", err)
	}
	if tier != Tier1Architecture {
		t.Errorf("expected Tier1Architecture, got %v", tier)
	}
	if status != StatusProposed {
		t.Errorf("expected StatusProposed for downgraded write, got %v", status)
	}
}

func TestAuthorizeWrite_Subagent_BlockedFromSovereign(t *testing.T) {
	enforcer := NewDefaultPolicyEnforcer()
	ctx := context.Background()

	subagentClaims := SubjectClaims{
		Subject: "agent-worktree-4",
		Role:    "subagent",
		Scopes:  []string{"memory:read", "memory:scratchpad:*"},
	}

	req := MemoryWriteRequest{
		Category: "security_policy",
		Content:  "Disable Airlock sandbox",
	}

	tier, status, err := enforcer.AuthorizeWrite(ctx, subagentClaims, req)
	if !errors.Is(err, ErrForbiddenAuthority) {
		t.Fatalf("expected ErrForbiddenAuthority, got %v", err)
	}
	if tier != Tier0Sovereign {
		t.Errorf("expected Tier0Sovereign, got %v", tier)
	}
	if status != StatusRejected {
		t.Errorf("expected StatusRejected for Tier 0 write, got %v", status)
	}
}

func TestValidateSupersession_ProductOwnerCannotSupersedeArchitecture(t *testing.T) {
	enforcer := NewDefaultPolicyEnforcer()
	ctx := context.Background()

	poClaims := SubjectClaims{
		Subject: "bob@corp.org",
		Role:    "product_owner",
		Scopes:  []string{"memory:product:write"},
	}

	err := enforcer.ValidateSupersession(ctx, poClaims, Tier1Architecture, "node-arch-1", "node-po-2", nil)
	if !errors.Is(err, ErrForbiddenAuthority) {
		t.Fatalf("expected ErrForbiddenAuthority when PO supersedes Arch, got %v", err)
	}
}

func TestValidateSupersession_ArchitectCanSupersedeArchitecture(t *testing.T) {
	enforcer := NewDefaultPolicyEnforcer()
	ctx := context.Background()

	archClaims := SubjectClaims{
		Subject: "alice@corp.org",
		Role:    "architect",
		Scopes:  []string{"memory:architecture:write"},
	}

	err := enforcer.ValidateSupersession(ctx, archClaims, Tier1Architecture, "node-arch-1", "node-arch-2", nil)
	if err != nil {
		t.Fatalf("expected architect supersession to succeed, got %v", err)
	}
}

func TestValidateSupersession_CycleDetection(t *testing.T) {
	enforcer := NewDefaultPolicyEnforcer()
	ctx := context.Background()

	archClaims := SubjectClaims{
		Subject: "alice@corp.org",
		Role:    "architect",
		Scopes:  []string{"memory:architecture:write"},
	}

	// Graph: node-3 supersedes node-2, node-2 supersedes node-1.
	// If someone attempts to make node-1 supersede node-3, that's a cycle: 1 -> 3 -> 2 -> 1
	dag := map[string][]string{
		"node-3": {"node-2"},
		"node-2": {"node-1"},
		"node-1": {},
	}

	getAncestors := func(id string) ([]string, error) {
		return dag[id], nil
	}

	// Attempting to supersede node-3 with node-1:
	// targetID = "node-3", supersedingID = "node-1"
	// ancestors of node-3 are node-2, whose ancestors are node-1 == supersedingID -> cycle!
	err := enforcer.ValidateSupersession(ctx, archClaims, Tier1Architecture, "node-3", "node-1", getAncestors)
	if !errors.Is(err, ErrCyclicSupersession) {
		t.Fatalf("expected ErrCyclicSupersession, got %v", err)
	}

	// Immediate self-loop: target == superseding
	errSelf := enforcer.ValidateSupersession(ctx, archClaims, Tier1Architecture, "node-1", "node-1", nil)
	if !errors.Is(errSelf, ErrCyclicSupersession) {
		t.Fatalf("expected ErrCyclicSupersession for self-loop, got %v", errSelf)
	}
}

func TestCategoryToDefaultTier_Learnings(t *testing.T) {
	cases := []struct {
		category string
		expected AuthorityTier
	}{
		{"learning", Tier1Architecture},
		{"architectural-learning", Tier1Architecture},
		{"lesson", Tier1Architecture},
		{"learnings", Tier1Architecture},
		{"accepted-rfc", Tier1Architecture},
		{"architecture", Tier1Architecture},
		{"general", Tier3Episodic},
	}

	for _, tc := range cases {
		tier := CategoryToDefaultTier(tc.category)
		if tier != tc.expected {
			t.Errorf("CategoryToDefaultTier(%q) = %v; want %v", tc.category, tier, tc.expected)
		}
	}
}
