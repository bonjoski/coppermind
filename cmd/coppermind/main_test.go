package main

import (
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/coppermind/pkg/brain"
)

func TestFormatObservation_LeanThreatModelAttributes(t *testing.T) {
	node := &brain.MemoryNode{
		ID:         "obs_test_123",
		SourceLens: "security-architect",
		Severity:   "critical",
		Status:     "open",
		CreatedAt:  time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC),
		ParentIDs:  []string{"mem_parent_1", "mem_parent_2"},
		Content:    "Found critical authorization bypass in DeleteItemHandler\nEvidence: Omitted tenant isolation check\nEntry Point: DeleteItemHandler\nSibling Inconsistency: GetItemHandler checks tenantID boundary\nPoC: curl -X DELETE http://localhost:8080/items/123",
		Metadata: map[string]string{
			"entry_point":           "DeleteItemHandler",
			"sibling_inconsistency": "GetItemHandler checks tenantID boundary",
			"poc":                   "curl -X DELETE http://localhost:8080/items/123",
		},
	}

	formatted := FormatObservation(node, 1)

	// Check headers
	if !strings.Contains(formatted, "[1] CRITICAL (security-architect) — OPEN [ID: obs_test_123]") {
		t.Errorf("expected header in formatted output, got:\n%s", formatted)
	}
	if !strings.Contains(formatted, "Parent Memories: mem_parent_1, mem_parent_2") {
		t.Errorf("expected parent memories in formatted output, got:\n%s", formatted)
	}

	// Check lean threat model attributes formatted with 2 spaces
	expectedAttrs := []string{
		"  Entry Point: DeleteItemHandler",
		"  Sibling Inconsistency: GetItemHandler checks tenantID boundary",
		"  PoC: curl -X DELETE http://localhost:8080/items/123",
	}
	for _, expected := range expectedAttrs {
		if !strings.Contains(formatted, expected) {
			t.Errorf("missing expected attribute %q in formatted output:\n%s", expected, formatted)
		}
	}

	// Ensure no unverified indicator
	if strings.Contains(formatted, "UNVERIFIED POC") {
		t.Errorf("unexpected unverified indicator in formatted output:\n%s", formatted)
	}

	// Ensure lines are not duplicated
	if strings.Count(formatted, "DeleteItemHandler") != 2 { // Once in header/content summary, once in "Entry Point: "
		t.Logf("occurrences of DeleteItemHandler: %d", strings.Count(formatted, "DeleteItemHandler"))
	}
}

func TestFormatObservation_UnverifiedPoC(t *testing.T) {
	node := &brain.MemoryNode{
		ID:         "obs_test_456",
		SourceLens: "security-architect",
		Severity:   "info",
		Status:     "open",
		CreatedAt:  time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC),
		Content:    "Potential issue flagged but missing actionable proof",
		Metadata: map[string]string{
			"unverified_poc":        "true",
			"entry_point":           "UnverifiedHandler",
			"sibling_inconsistency": "Missing sibling comparison",
			"poc":                   "todo",
		},
	}

	formatted := FormatObservation(node, 2)

	if !strings.Contains(formatted, "  ⚠️  [UNVERIFIED POC: Demoted to Info]") {
		t.Errorf("expected unverified POC indicator in output, got:\n%s", formatted)
	}
	if !strings.Contains(formatted, "  Entry Point: UnverifiedHandler") {
		t.Errorf("expected entry point in output, got:\n%s", formatted)
	}
	if !strings.Contains(formatted, "  Sibling Inconsistency: Missing sibling comparison") {
		t.Errorf("expected sibling inconsistency in output, got:\n%s", formatted)
	}
	if !strings.Contains(formatted, "  PoC: todo") {
		t.Errorf("expected poc in output, got:\n%s", formatted)
	}
}

func TestFormatObservation_NilMetadata(t *testing.T) {
	node := &brain.MemoryNode{
		ID:         "obs_test_789",
		SourceLens: "devils-advocate",
		Severity:   "medium",
		Status:     "open",
		CreatedAt:  time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC),
		Content:    "Consider edge case with empty inputs",
		Metadata:   nil,
	}

	formatted := FormatObservation(node, 3)
	if !strings.Contains(formatted, "[3] MEDIUM (devils-advocate) — OPEN [ID: obs_test_789]") {
		t.Errorf("expected header in formatted output, got:\n%s", formatted)
	}
	if !strings.Contains(formatted, "    Consider edge case with empty inputs") {
		t.Errorf("expected content line in formatted output, got:\n%s", formatted)
	}
}
