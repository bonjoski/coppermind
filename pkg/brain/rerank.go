package brain

import (
	"math"
	"sort"
	"strings"
	"time"

	"github.com/bonjoski/coppermind/pkg/scope"
)

// ScoreBreakdown exposes normalized per-signal scoring components for `--explain` and Brain Explorer.
type ScoreBreakdown struct {
	HybridScore   float32 `json:"hybrid_score"`
	RecencyACTR   float32 `json:"recency_actr"`
	RepoAffinity  float32 `json:"repo_affinity"`
	ScopeAffinity float32 `json:"scope_affinity,omitempty"`
	GraphBoost    float32 `json:"graph_boost"`
	TierWeight    float32 `json:"tier_weight"`
	FinalScore    float32 `json:"final_score"`
}

// RerankConfig controls composite relevance, ACT-R reinforcement, repo/scope affinity, and MMR diversity.
type RerankConfig struct {
	ActiveRepo       string
	ActiveBranch     string
	ActiveScope      string
	MMRLambda        float32 // Default 0.75 (0 = pure diversity, 1 = pure relevance)
	HalfLifeDays     float64 // Default 30.0
	Tier01RecencyMin float32 // Default 0.70 (core architecture invariants never decay away)
	DisableMMR       bool
	Limit            int
	Now              time.Time
}

// DefaultRerankConfig returns balanced production reranking defaults.
func DefaultRerankConfig() RerankConfig {
	return RerankConfig{
		MMRLambda:        0.75,
		HalfLifeDays:     30.0,
		Tier01RecencyMin: 0.70,
		Now:              time.Now(),
	}
}

// RerankResults applies normalized composite scoring (hybrid + ACT-R recency/access +
// ambient repo/branch affinity + graph boost + epistemic authority tier) followed by
// Maximal Marginal Relevance (MMR) deduplication.
func RerankResults(results []*SearchResult, cfg RerankConfig) []*SearchResult {
	if len(results) == 0 {
		return results
	}
	if cfg.HalfLifeDays <= 0 {
		cfg.HalfLifeDays = 30.0
	}
	if cfg.MMRLambda <= 0 || cfg.MMRLambda > 1 {
		cfg.MMRLambda = 0.75
	}
	if cfg.Tier01RecencyMin <= 0 {
		cfg.Tier01RecencyMin = 0.70
	}
	if cfg.Now.IsZero() {
		cfg.Now = time.Now()
	}

	// Normalize raw hybrid/semantic score into [0, 1] while preserving relative spread.
	var maxRaw float32
	for _, r := range results {
		if r.Score > maxRaw {
			maxRaw = r.Score
		}
	}

	for _, r := range results {
		node := r.Node
		if node == nil {
			continue
		}

		hybridNorm := r.Score
		if maxRaw > 0 && maxRaw < 0.20 {
			// Normalize raw RRF scores (typically ~0.016-0.033) into interpretable [0, 1] range.
			hybridNorm = clamp01(r.Score / maxRaw)
		} else {
			hybridNorm = clamp01(r.Score)
		}

		recency := computeACTRScore(node, cfg)
		repoAff := computeRepoAffinity(node, cfg.ActiveRepo, cfg.ActiveBranch)
		scopeAff := scope.Affinity(node.Scope, cfg.ActiveScope)
		graphBoost := float32(0.0)
		if len(r.GraphLinks) > 0 {
			graphBoost = clamp01(0.45 + 0.15*float32(len(r.GraphLinks)))
		}

		tierW := authorityTierWeight(node.AuthorityTier)
		var rawComposite float32
		if cfg.ActiveScope != "" {
			rawComposite = 0.54*hybridNorm + 0.16*recency + 0.14*scopeAff + 0.08*repoAff + 0.08*graphBoost
		} else {
			rawComposite = 0.58*hybridNorm + 0.18*recency + 0.14*repoAff + 0.10*graphBoost
		}
		finalScore := clamp01(rawComposite * tierW)

		r.Score = finalScore
		r.Breakdown = &ScoreBreakdown{
			HybridScore:   hybridNorm,
			RecencyACTR:   recency,
			RepoAffinity:  repoAff,
			ScopeAffinity: scopeAff,
			GraphBoost:    graphBoost,
			TierWeight:    tierW,
			FinalScore:    finalScore,
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Score > results[j].Score
	})

	limit := cfg.Limit
	if limit <= 0 || limit > len(results) {
		limit = len(results)
	}

	if cfg.DisableMMR || limit <= 1 || len(results) <= 1 {
		return results[:limit]
	}

	return selectMMR(results, limit, cfg.MMRLambda)
}

func computeACTRScore(node *MemoryNode, cfg RerankConfig) float32 {
	refTime := node.UpdatedAt
	if refTime.IsZero() {
		refTime = node.CreatedAt
	}
	if !node.LastAccessedAt.IsZero() && node.LastAccessedAt.After(refTime) && node.Provenance == ProvenanceLocalWorkspace {
		refTime = node.LastAccessedAt
	}

	ageDays := cfg.Now.Sub(refTime).Hours() / 24.0
	if ageDays < 0 {
		ageDays = 0
	}

	// Exponential recency decay with half-life
	decay := math.Exp(-math.Ln2 * ageDays / cfg.HalfLifeDays)

	// Security invariant: TAINT_* memories NEVER receive ACT-R access reinforcement.
	accessBoost := 0.0
	if node.Provenance == ProvenanceLocalWorkspace && node.AccessCount > 0 {
		accessBoost = 0.25 * math.Log1p(float64(node.AccessCount)) / (1.0 + 0.25*math.Log1p(float64(node.AccessCount)))
	}

	score := float32(clamp01(float32(0.75*decay + accessBoost)))

	// Epistemic invariant: TIER_0 and TIER_1 architectural rules never decay below floor.
	if node.AuthorityTier == "TIER_0_SOVEREIGN" || node.AuthorityTier == "TIER_1_ARCHITECTURE" {
		if score < cfg.Tier01RecencyMin {
			score = cfg.Tier01RecencyMin
		}
	}
	return score
}

func computeRepoAffinity(node *MemoryNode, activeRepo, activeBranch string) float32 {
	if activeRepo == "" {
		return 0.50
	}
	nodeRepo := ""
	nodeBranch := ""
	if node.Metadata != nil {
		nodeRepo = strings.TrimSpace(node.Metadata["git_repo"])
		nodeBranch = strings.TrimSpace(node.Metadata["git_branch"])
	}
	if nodeRepo == "" {
		// Check session fallback (e.g. "index:<repo>" or "<repo>")
		if strings.HasPrefix(node.SessionID, "index:") {
			nodeRepo = strings.TrimPrefix(node.SessionID, "index:")
		} else if strings.EqualFold(node.SessionID, activeRepo) {
			nodeRepo = node.SessionID
		}
	}
	if strings.EqualFold(nodeRepo, activeRepo) {
		if activeBranch != "" && strings.EqualFold(nodeBranch, activeBranch) {
			return 1.0
		}
		return 0.70
	}
	return 0.15
}

func authorityTierWeight(tier string) float32 {
	switch tier {
	case "TIER_0_SOVEREIGN":
		return 1.25
	case "TIER_1_ARCHITECTURE", "TIER_2_PRODUCT":
		return 1.05
	case "TIER_2_MENTOR_CAPSULE":
		return 0.90
	case "TIER_3_EPISODIC", "TIER_3_DERIVED":
		return 0.80
	case "TIER_4_SCRATCHPAD":
		return 0.55
	default:
		return 0.85
	}
}

func selectMMR(candidates []*SearchResult, k int, lambda float32) []*SearchResult {
	selected := make([]*SearchResult, 0, k)
	used := make([]bool, len(candidates))

	// Always pick the top-1 highest-scoring result first.
	selected = append(selected, candidates[0])
	used[0] = true

	for len(selected) < k {
		bestIdx := -1
		bestMMR := float32(-math.MaxFloat32)

		for i, cand := range candidates {
			if used[i] {
				continue
			}
			var maxSim float32
			for _, sel := range selected {
				sim := nodeSimilarity(cand.Node, sel.Node)
				if sim > maxSim {
					maxSim = sim
				}
			}
			mmrScore := lambda*cand.Score - (1.0-lambda)*maxSim
			if mmrScore > bestMMR {
				bestMMR = mmrScore
				bestIdx = i
			}
		}
		if bestIdx == -1 {
			break
		}
		selected = append(selected, candidates[bestIdx])
		used[bestIdx] = true
	}
	return selected
}

func nodeSimilarity(a, b *MemoryNode) float32 {
	if a == nil || b == nil {
		return 0
	}
	if len(a.Vector) > 0 && len(a.Vector) == len(b.Vector) {
		var dot float32
		for i := range a.Vector {
			dot += a.Vector[i] * b.Vector[i]
		}
		return clamp01(dot)
	}
	// Fallback Jaccard overlap over content tokens when dimensions differ.
	ta := tokenSet(a.Content)
	tb := tokenSet(b.Content)
	if len(ta) == 0 || len(tb) == 0 {
		return 0
	}
	inter := 0
	for k := range ta {
		if tb[k] {
			inter++
		}
	}
	union := len(ta) + len(tb) - inter
	if union == 0 {
		return 0
	}
	return float32(inter) / float32(union)
}

func tokenSet(s string) map[string]bool {
	fields := strings.Fields(strings.ToLower(s))
	set := make(map[string]bool, len(fields))
	for _, f := range fields {
		if len(f) > 2 {
			set[f] = true
		}
	}
	return set
}

func clamp01(v float32) float32 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}
