package graph

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/scope"
)

// RelationType enumerates allowlisted knowledge graph edge relations.
type RelationType string

const (
	RelTouchesFile        RelationType = "touches_file"
	RelTouchesSymbol      RelationType = "touches_symbol"
	RelReferencesRFC      RelationType = "references_rfc"
	RelReferencesAdvisory RelationType = "references_advisory"
	RelBelongsToRepo      RelationType = "belongs_to_repo"
	RelCausedBy           RelationType = "caused_by"
	RelContradicts        RelationType = "contradicts"
	RelImplements         RelationType = "implements"
	RelSupersedes         RelationType = "supersedes"
	RelRelatedTo          RelationType = "related_to"

	// MaxEdgesPerNode caps deterministic entity extraction to prevent hub-node DoS.
	MaxEdgesPerNode = 32

	// MaxGraphHops hard-caps BFS traversal depth.
	MaxGraphHops = 2

	// MaxExpandedNodes hard-caps neighbor expansion fan-out per query.
	MaxExpandedNodes = 50
)

// Edge represents a typed directed edge in the Coppermind knowledge graph.
type Edge struct {
	ID           string       `json:"id"`
	SourceID     string       `json:"source_id"`
	TargetID     string       `json:"target_id,omitempty"`
	TargetEntity string       `json:"target_entity,omitempty"` // Canonical normalized entity (e.g. "file:pkg/mcp/server.go")
	Relation     RelationType `json:"relation"`
	Weight       float32      `json:"weight"`
	Derived      bool         `json:"derived"`
	CreatedAt    time.Time    `json:"created_at"`
}

// Precompiled linear-time RE2 entity extractors (ReDoS-safe, <0.3ms).
var (
	reFilePath = regexp.MustCompile(`\b(?:pkg|cmd|docs|internal|test|scripts|capsules|deploy)/[A-Za-z0-9_./-]{1,120}\.[a-z0-9]{1,10}\b`)
	reRFC      = regexp.MustCompile(`\b(?:RFC-\d{4}-\d{2}-\d{2}-\d{1,4}|ADR-\d{3,4})\b`)
	reAdvisory = regexp.MustCompile(`\b(?:CVE-\d{4}-\d{4,7}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})\b`)
	reSymbol   = regexp.MustCompile("`([A-Z][A-Za-z0-9_]{1,40}\\.[A-Za-z0-9_]{1,50}|[a-z][a-z0-9_]{1,24}\\.[A-Z][A-Za-z0-9_]{1,50})`")
)

// IsValidRelation checks whether rel belongs to the strict relation allowlist.
func IsValidRelation(rel RelationType) bool {
	switch rel {
	case RelTouchesFile, RelTouchesSymbol, RelReferencesRFC, RelReferencesAdvisory,
		RelBelongsToRepo, RelCausedBy, RelContradicts, RelImplements, RelSupersedes, RelRelatedTo:
		return true
	default:
		return false
	}
}

// NormalizeFileEntity canonicalizes a workspace relative path into a graph entity key.
func NormalizeFileEntity(path string) string {
	clean := filepath.ToSlash(filepath.Clean(strings.TrimSpace(path)))
	clean = strings.TrimPrefix(clean, "./")
	clean = strings.TrimPrefix(clean, "/")
	if clean == "" || clean == "." || strings.HasPrefix(clean, "..") {
		return ""
	}
	return "file:" + clean
}

// ExtractEdges deterministically extracts up to MaxEdgesPerNode typed entity-relation edges
// from a MemoryNode with zero LLM calls and linear RE2 complexity (<0.3ms).
func ExtractEdges(node *brain.MemoryNode) []Edge {
	if node == nil || node.ID == "" {
		return nil
	}

	now := node.CreatedAt
	if now.IsZero() {
		now = time.Now()
	}

	// Bound scanned content length to prevent pathological input slowdowns.
	scanText := node.Content
	if len(scanText) > 32768 {
		scanText = scanText[:32768]
	}

	seen := make(map[string]struct{}, MaxEdgesPerNode)
	edges := make([]Edge, 0, 8)
	addEdge := func(targetID, targetEntity string, rel RelationType, weight float32) {
		if len(edges) >= MaxEdgesPerNode {
			return
		}
		// Security invariant: untrusted web memories cannot emit canonical implements/supersedes edges.
		if node.Provenance == brain.ProvenanceUntrustedWeb && (rel == RelImplements || rel == RelSupersedes) {
			return
		}
		key := string(rel) + "|" + targetID + "|" + targetEntity
		if _, dup := seen[key]; dup {
			return
		}
		seen[key] = struct{}{}
		sum := sha256.Sum256([]byte(node.ID + ":" + key))
		edges = append(edges, Edge{
			ID:           "edge_" + hex.EncodeToString(sum[:8]),
			SourceID:     node.ID,
			TargetID:     targetID,
			TargetEntity: targetEntity,
			Relation:     rel,
			Weight:       weight,
			Derived:      node.Derived,
			CreatedAt:    now,
		})
	}

	// 1. Metadata-derived canonical entities (highest precision)
	if node.Metadata != nil {
		if p := NormalizeFileEntity(node.Metadata["path"]); p != "" {
			addEdge("", p, RelTouchesFile, 1.0)
		}
		if sym := strings.TrimSpace(node.Metadata["symbol"]); sym != "" && len(sym) <= 120 {
			addEdge("", "symbol:"+sym, RelTouchesSymbol, 1.0)
		}
		if repo := strings.TrimSpace(node.Metadata["git_repo"]); repo != "" && len(repo) <= 80 {
			addEdge("", "repo:"+strings.ToLower(repo), RelBelongsToRepo, 0.7)
		}
	}

	// 2. Explicit structural node links (SupersedesID, ParentIDs, AdvisoryRef)
	if node.SupersedesID != "" {
		addEdge(node.SupersedesID, "", RelSupersedes, 1.0)
	}
	if ref := strings.TrimSpace(node.AdvisoryRef); ref != "" {
		if strings.HasPrefix(strings.ToUpper(ref), "RFC-") || strings.HasPrefix(strings.ToUpper(ref), "ADR-") {
			addEdge("", "rfc:"+strings.ToUpper(ref), RelReferencesRFC, 1.0)
		} else if strings.HasPrefix(strings.ToUpper(ref), "CVE-") || strings.HasPrefix(strings.ToUpper(ref), "GHSA-") {
			addEdge("", "advisory:"+strings.ToUpper(ref), RelReferencesAdvisory, 1.0)
		}
	}
	for _, pid := range node.ParentIDs {
		if pid != "" && pid != node.ID {
			addEdge(pid, "", RelRelatedTo, 0.85)
		}
	}

	// 3. Content-extracted entities (capped at MaxEdgesPerNode)
	for _, m := range reFilePath.FindAllString(scanText, MaxEdgesPerNode) {
		if ent := NormalizeFileEntity(m); ent != "" {
			addEdge("", ent, RelTouchesFile, 0.9)
		}
	}
	for _, m := range reRFC.FindAllString(scanText, MaxEdgesPerNode) {
		addEdge("", "rfc:"+strings.ToUpper(m), RelReferencesRFC, 0.95)
	}
	for _, m := range reAdvisory.FindAllString(scanText, MaxEdgesPerNode) {
		addEdge("", "advisory:"+strings.ToUpper(m), RelReferencesAdvisory, 0.95)
	}
	for _, sm := range reSymbol.FindAllStringSubmatch(scanText, MaxEdgesPerNode) {
		if len(sm) >= 2 {
			addEdge("", "symbol:"+sm[1], RelTouchesSymbol, 0.85)
		}
	}

	return edges
}

// polarityPairs detect likely directive conflicts between two high-authority architectural statements.
var polarityPairs = [][2]string{
	{"always", "never"},
	{"must ", "must not"},
	{"enable", "disable"},
	{"allow", "deny"},
	{"use ", "avoid "},
	{"use ", "replace "},
	{"deprecated", "active"},
	{"synchronous", "asynchronous"},
	{"required", "forbidden"},
}

// DetectConflicts checks whether a newly stored high-authority memory potentially conflicts
// with an existing active TIER_0/TIER_1 invariant without an explicit supersedes link.
func DetectConflicts(ctx context.Context, mgr *brain.Manager, candidate *brain.MemoryNode) []brain.ConflictWarning {
	if mgr == nil || candidate == nil || candidate.SupersedesID != "" || candidate.Derived {
		return nil
	}
	if candidate.AuthorityTier != "TIER_0_SOVEREIGN" && candidate.AuthorityTier != "TIER_1_ARCHITECTURE" {
		return nil
	}

	recallReq := brain.RecallRequest{
		Query:      candidate.Content,
		Limit:      5,
		Hybrid:     true,
		DisableMMR: true,
	}
	if candidate.Scope != "" {
		recallReq.Scope = candidate.Scope
		recallReq.ScopeMode = scope.ModeAncestors
		recallReq.ActiveScope = candidate.Scope
	}
	results, err := mgr.Recall(ctx, recallReq)
	if err != nil || len(results) == 0 {
		return nil
	}

	candLower := strings.ToLower(candidate.Content)
	var warnings []brain.ConflictWarning

	for _, r := range results {
		if r == nil || r.Node == nil || r.Node.ID == candidate.ID {
			continue
		}
		if r.Node.AuthorityTier != "TIER_0_SOVEREIGN" && r.Node.AuthorityTier != "TIER_1_ARCHITECTURE" {
			continue
		}
		if r.Score < 0.65 {
			continue
		}
		existingLower := strings.ToLower(r.Node.Content)
		if existingLower == candLower {
			continue
		}

		if hasPolarityContrast(candLower, existingLower) || r.Score >= 0.82 {
			snippet := r.Node.Content
			if len(snippet) > 140 {
				snippet = snippet[:140] + "..."
			}
			action := fmt.Sprintf("If this replaces %s, re-store with supersedes=%q and a rationale.", r.Node.ID, r.Node.ID)
			if r.Node.Scope != candidate.Scope {
				parentLabel := r.Node.Scope
				if parentLabel == "" {
					parentLabel = "(vault-global)"
				}
				action = fmt.Sprintf("Ancestor refinement of %s in scope %q: keep both for scoped exception, or target scope %q directly to supersede.", r.Node.ID, parentLabel, r.Node.Scope)
			}
			warnings = append(warnings, brain.ConflictWarning{
				ConflictingNodeID: r.Node.ID,
				AuthorityTier:     r.Node.AuthorityTier,
				Similarity:        r.Score,
				Summary:           snippet,
				SuggestedAction:   action,
			})
			if len(warnings) >= 3 {
				break
			}
		}
	}
	return warnings
}

func hasPolarityContrast(a, b string) bool {
	for _, pair := range polarityPairs {
		aHas0 := strings.Contains(a, pair[0])
		aHas1 := strings.Contains(a, pair[1])
		bHas0 := strings.Contains(b, pair[0])
		bHas1 := strings.Contains(b, pair[1])
		if (aHas0 && bHas1 && !aHas1) || (aHas1 && bHas0 && !aHas0) {
			return true
		}
	}
	return false
}
