package capsules

import _ "embed"

// DefaultDeterministicWebBasicsJSON embeds the curated 6-card Deterministic Web Basics mentor pack.
//
//go:embed deterministic-web-basics.mentor.json
var DefaultDeterministicWebBasicsJSON []byte

// DefaultAIAppAndRAGSafetyJSON embeds the curated 6-card AI App & RAG Safety mentor pack.
//
//go:embed ai-app-and-rag-safety.mentor.json
var DefaultAIAppAndRAGSafetyJSON []byte

// DefaultMCPToolBoundariesJSON embeds the curated 6-card MCP Tool Boundaries mentor pack.
//
//go:embed mcp-tool-boundaries.mentor.json
var DefaultMCPToolBoundariesJSON []byte

// DefaultPOAbuseCaseCriteriaJSON embeds the curated 10-card PO & Requirements starter pack
// so `coppermind requirements` and `coppermind_recall(lens="requirements")` work zero-config out of the box.
//
//go:embed po-abuse-case-criteria.mentor.json
var DefaultPOAbuseCaseCriteriaJSON []byte

// DefaultMentorCapsulePayloads returns the 3 embedded v1.0 Security Mentor Capsule JSON payloads
// (18 curated cards total) in canonical deterministic order for zero-config fallback recall.
func DefaultMentorCapsulePayloads() [][]byte {
	return [][]byte{
		DefaultDeterministicWebBasicsJSON,
		DefaultAIAppAndRAGSafetyJSON,
		DefaultMCPToolBoundariesJSON,
	}
}
