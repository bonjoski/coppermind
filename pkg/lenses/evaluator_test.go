package lenses

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/router"
)

func TestEnforcePoCGate(t *testing.T) {
	// 1. Nil finding guard
	if EnforcePoCGate(nil) {
		t.Errorf("expected EnforcePoCGate(nil) to return false")
	}

	// 2. Info and Low severity findings do not require PoCs
	infoFinding := &Finding{
		Severity: "info",
		Summary:  "Informational observation without exploit",
		PoC:      "",
	}
	if !EnforcePoCGate(infoFinding) {
		t.Errorf("expected info finding to pass PoC gate")
	}
	if infoFinding.Severity != "info" || infoFinding.UnverifiedPoC {
		t.Errorf("info finding mutated unexpectedly: %+v", infoFinding)
	}

	lowFinding := &Finding{
		Severity: "low",
		Summary:  "Low severity hygiene issue",
		PoC:      "",
	}
	if !EnforcePoCGate(lowFinding) {
		t.Errorf("expected low finding to pass PoC gate")
	}
	if lowFinding.Severity != "low" || lowFinding.UnverifiedPoC {
		t.Errorf("low finding mutated unexpectedly: %+v", lowFinding)
	}

	// 3. Medium/High/Critical findings failing the gate
	testCasesFail := []struct {
		name     string
		finding  Finding
		expected string
	}{
		{
			name: "empty PoC on high severity",
			finding: Finding{
				Severity: "high",
				Summary:  "Missing auth check on delete endpoint",
				PoC:      "",
			},
		},
		{
			name: "whitespace-only PoC on critical severity",
			finding: Finding{
				Severity: "critical",
				Summary:  "Remote code execution",
				PoC:      "   \t\n   ",
			},
		},
		{
			name: "too short PoC (<15 chars) on medium severity",
			finding: Finding{
				Severity: "medium",
				Summary:  "IDOR flaw",
				PoC:      "curl http://a",
			},
		},
		{
			name: "placeholder todo in PoC",
			finding: Finding{
				Severity: "high",
				Summary:  "Cross-tenant data leak",
				PoC:      "TODO: write reproduction curl command later",
			},
		},
		{
			name: "placeholder n/a in PoC",
			finding: Finding{
				Severity: "critical",
				Summary:  "Arbitrary file write",
				PoC:      "N/A - reproduction not applicable here",
			},
		},
		{
			name: "placeholder not applicable in PoC",
			finding: Finding{
				Severity: "medium",
				Summary:  "Information disclosure",
				PoC:      "This finding is not applicable for curl reproduction",
			},
		},
		{
			name: "plain prose lacking executable structure (>=15 chars)",
			finding: Finding{
				Severity: "high",
				Summary:  "Command injection sink",
				PoC:      "An attacker could provide bad input to trigger the flaw",
			},
		},
	}

	for _, tc := range testCasesFail {
		t.Run(tc.name, func(t *testing.T) {
			f := tc.finding
			origSev := f.Severity
			ok := EnforcePoCGate(&f)
			if ok {
				t.Fatalf("expected finding with severity %s to fail PoC gate", origSev)
			}
			if f.Severity != "info" {
				t.Errorf("expected failed finding severity to be demoted to 'info', got %q", f.Severity)
			}
			if !f.UnverifiedPoC {
				t.Errorf("expected failed finding to have UnverifiedPoC == true")
			}
		})
	}

	// 4. Medium/High/Critical findings passing the gate
	testCasesPass := []struct {
		name    string
		finding Finding
	}{
		{
			name: "valid curl command on high severity",
			finding: Finding{
				Severity: "high",
				Summary:  "IDOR bypass on item deletion",
				PoC:      "curl -X DELETE http://localhost:8080/items/123 -H 'Authorization: Bearer token'",
			},
		},
		{
			name: "valid http URL request structure on critical severity",
			finding: Finding{
				Severity: "critical",
				Summary:  "Unauthenticated admin endpoint",
				PoC:      "POST http://127.0.0.1:9090/admin/reset?force=true",
			},
		},
		{
			name: "valid JSON payload structure {} on medium severity",
			finding: Finding{
				Severity: "medium",
				Summary:  "Parameter injection flaw",
				PoC:      `{"tenant_id": "other_tenant", "target": "root"}`,
			},
		},
		{
			name: "valid function invocation structure () on high severity",
			finding: Finding{
				Severity: "high",
				Summary:  "Re-entrancy bug in handler",
				PoC:      "triggerExploit(targetSession, 0xdeadbeef)",
			},
		},
		{
			name: "valid shell parameter expansion structure $ on critical severity",
			finding: Finding{
				Severity: "critical",
				Summary:  "Command injection in exec wrapper",
				PoC:      "sh -c \"run_task $(id)\"",
			},
		},
	}

	for _, tc := range testCasesPass {
		t.Run(tc.name, func(t *testing.T) {
			f := tc.finding
			origSev := f.Severity
			ok := EnforcePoCGate(&f)
			if !ok {
				t.Fatalf("expected valid finding to pass PoC gate")
			}
			if f.Severity != origSev {
				t.Errorf("expected severity to remain %q, got %q", origSev, f.Severity)
			}
			if f.UnverifiedPoC {
				t.Errorf("expected UnverifiedPoC to be false for passed finding")
			}
		})
	}
}

func TestParseAndSanitizeResponse_DifferentialSecurity(t *testing.T) {
	// 1. Structured JSON with full lean threat-model fields and valid PoC
	rawContent := `{
		"findings": [
			{
				"severity": "high",
				"category": "differential_auth",
				"entry_point": "DeleteItemHandler",
				"sibling_inconsistency": "GetItem checks tenantID, DeleteItem omits tenantID check",
				"summary": "IDOR wipe vulnerability: cross-tenant deletion",
				"poc": "curl -X DELETE http://localhost:8080/items/victim-item -H 'Authorization: Bearer attacker-token'"
			}
		]
	}`

	resp, err := parseAndSanitizeResponse(rawContent)
	if err != nil {
		t.Fatalf("parseAndSanitizeResponse failed: %v", err)
	}

	if len(resp.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(resp.Findings))
	}

	f := resp.Findings[0]
	if f.Severity != "high" {
		t.Errorf("expected severity 'high', got %q", f.Severity)
	}
	if f.Category != "differential_auth" {
		t.Errorf("expected category 'differential_auth', got %q", f.Category)
	}
	if f.EntryPoint != "DeleteItemHandler" {
		t.Errorf("expected entry_point 'DeleteItemHandler', got %q", f.EntryPoint)
	}
	if f.SiblingInconsistency != "GetItem checks tenantID, DeleteItem omits tenantID check" {
		t.Errorf("expected sibling_inconsistency populated, got %q", f.SiblingInconsistency)
	}
	if !strings.Contains(f.PoC, "curl -X DELETE") {
		t.Errorf("expected PoC populated, got %q", f.PoC)
	}
	if f.UnverifiedPoC {
		t.Errorf("expected UnverifiedPoC to be false for valid PoC")
	}

	// 2. Finding with differential_auth but missing PoC is automatically demoted to info
	rawNoPoC := `{
		"findings": [
			{
				"severity": "critical",
				"category": "differential_auth",
				"entry_point": "UpdateItemHandler",
				"sibling_inconsistency": "Missing tenant check",
				"summary": "Cross-tenant state mutation",
				"poc": ""
			}
		]
	}`

	respNoPoC, err := parseAndSanitizeResponse(rawNoPoC)
	if err != nil {
		t.Fatalf("parseAndSanitizeResponse failed: %v", err)
	}
	if len(respNoPoC.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(respNoPoC.Findings))
	}
	fDemoted := respNoPoC.Findings[0]
	if fDemoted.Severity != "info" {
		t.Errorf("expected finding without PoC to be demoted to 'info', got %q", fDemoted.Severity)
	}
	if !fDemoted.UnverifiedPoC {
		t.Errorf("expected UnverifiedPoC == true for finding without PoC")
	}

	// 3. Secret quarantine in PoC and fields
	rawSecret := `{
		"findings": [
			{
				"severity": "high",
				"category": "differential_auth",
				"entry_point": "AuthHandler",
				"sibling_inconsistency": "Leaked key",
				"summary": "Detected credentials in endpoint",
				"poc": "curl -H 'Authorization: -----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0\n-----END RSA PRIVATE KEY-----' http://localhost:8080"
			}
		]
	}`

	respSecret, err := parseAndSanitizeResponse(rawSecret)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	fSec := respSecret.Findings[0]
	if strings.Contains(fSec.PoC, "BEGIN RSA PRIVATE KEY") {
		t.Errorf("secret quarantine failed: private key leaked into PoC: %s", fSec.PoC)
	}
	if !strings.Contains(fSec.PoC, "REDACTED") {
		t.Errorf("expected PoC secret to be redacted, got: %s", fSec.PoC)
	}
}

type mockEvalRouter struct {
	completeFn func(ctx context.Context, req *router.CompletionRequest) (*router.CompletionResponse, error)
}

func (m *mockEvalRouter) Complete(ctx context.Context, req *router.CompletionRequest) (*router.CompletionResponse, error) {
	if m.completeFn != nil {
		return m.completeFn(ctx, req)
	}
	return &router.CompletionResponse{Content: `{"findings":[]}`}, nil
}

func (m *mockEvalRouter) Reflect(ctx context.Context, sessionID string, memories []*brain.MemoryNode) (string, error) {
	return "", nil
}

func (m *mockEvalRouter) DistillDecisions(ctx context.Context, sessionID string, memories []*brain.MemoryNode) (string, error) {
	return "", nil
}

func TestEvaluateCandidate_ContextDeadlineEnforcement(t *testing.T) {
	lens := &LensConfig{
		Name:         "security-architect",
		Model:        "local-coder",
		SystemPrompt: "Auditor",
	}
	candidate := &brain.MemoryNode{
		ID:        "cand_1",
		Content:   "func test() {}",
		CreatedAt: time.Now(),
	}

	// 1. Verify deadline is set to <= 15s even if parent ctx has no deadline
	var observedDeadline time.Time
	var hadDeadline bool
	rtr := &mockEvalRouter{
		completeFn: func(ctx context.Context, req *router.CompletionRequest) (*router.CompletionResponse, error) {
			observedDeadline, hadDeadline = ctx.Deadline()
			return &router.CompletionResponse{Content: `{"findings":[]}`}, nil
		},
	}

	start := time.Now()
	_, err := EvaluateCandidate(context.Background(), lens, candidate, nil, rtr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hadDeadline {
		t.Fatalf("expected context passed to router to have a deadline enforced")
	}
	remaining := time.Until(observedDeadline)
	if remaining > 15*time.Second || remaining < 14*time.Second {
		t.Errorf("expected deadline around 15s, got remaining duration: %v (elapsed: %v)", remaining, time.Since(start))
	}

	// 2. Verify timeout triggers error when router blocks past deadline
	slowRtr := &mockEvalRouter{
		completeFn: func(ctx context.Context, req *router.CompletionRequest) (*router.CompletionResponse, error) {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(100 * time.Millisecond):
				return &router.CompletionResponse{Content: `{"findings":[]}`}, nil
			}
		},
	}

	// Create a short-timeout parent context
	shortCtx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	_, err = EvaluateCandidate(shortCtx, lens, candidate, nil, slowRtr)
	if err == nil {
		t.Errorf("expected error when context deadline exceeded, got nil")
	}
	if !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Errorf("expected context deadline exceeded error, got: %v", err)
	}
}
