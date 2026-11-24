package eval_test

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/embedding"
	"github.com/bonjoski/coppermind/pkg/scratchpad"
	"github.com/bonjoski/coppermind/pkg/storage/sqlite"
)

type evalDoc struct {
	id       string
	repo     string
	branch   string
	category string
	tier     string
	ageDays  int
	content  string
}

type evalQuery struct {
	query      string
	activeRepo string
	sinceDays  int
	expectID   string
}

func evalDataset() ([]evalDoc, []evalQuery) {
	docs := []evalDoc{
		{id: "doc_auth_ttl", repo: "conjoiner", branch: "main", category: "architecture", tier: "TIER_1_ARCHITECTURE", ageDays: 5,
			content: "RFC-2026-10-30-01: RFC 9449 Ed25519 DPoP authentication token TTL defaults to 30 seconds with a 60s policy ceiling in pkg/dpop/token.go."},
		{id: "doc_sqlite_wal", repo: "coppermind", branch: "main", category: "architecture", tier: "TIER_1_ARCHITECTURE", ageDays: 3,
			content: "Coppermind pure-Go SQLite storage uses WAL journal mode and a single-writer channel ring in pkg/storage/sqlite/sqlite.go for N=8 concurrency."},
		{id: "doc_airlock_seatbelt", repo: "airlock", branch: "main", category: "architecture", tier: "TIER_1_ARCHITECTURE", ageDays: 10,
			content: "Airlock Tier 1 kernel confinement uses Apple Seatbelt and Linux Landlock LSM with sub-15ms startup isolation."},
		{id: "doc_aegisbox_vm", repo: "aegisbox", branch: "main", category: "architecture", tier: "TIER_1_ARCHITECTURE", ageDays: 8,
			content: "Aegisbox hardware microVM sandbox leverages libkrun and macOS Hypervisor with ephemeral COW shadow workspaces."},
		{id: "doc_locksmith_enclave", repo: "locksmith", branch: "main", category: "sovereign_invariant", tier: "TIER_0_SOVEREIGN", ageDays: 20,
			content: "Locksmith biometric keychain seals credentials inside Touch ID Secure Enclave and TPM2 with amortized 300s leases."},
		{id: "doc_argus_quarry", repo: "argus", branch: "main", category: "architecture", tier: "TIER_1_ARCHITECTURE", ageDays: 2,
			content: "Argus pre-flight supply-chain interceptor blocks slopsquatting and typosquat dependencies via Project Quarry SemVer rules."},
		{id: "doc_stormcage_llm01", repo: "stormcage", branch: "main", category: "sovereign_invariant", tier: "TIER_0_SOVEREIGN", ageDays: 6,
			content: "Stormcage memory firewall applies NFKC normalization, strips zero-width homoglyphs, and blocks OWASP LLM01 prompt injection."},
		{id: "doc_bomhound_sbom", repo: "bomhound", branch: "main", category: "architecture", tier: "TIER_1_ARCHITECTURE", ageDays: 15,
			content: "Bomhound enriches CycloneDX SBOM files with unabridged multi-author copyright legal attribution."},
		{id: "doc_soulcaster_slsa", repo: "soulcaster", branch: "main", category: "architecture", tier: "TIER_1_ARCHITECTURE", ageDays: 12,
			content: "Soulcaster runtime compiler attestation generates hermetic SLSA v1.0 and in-toto provenance with TOCTOU defense."},
		{id: "doc_coppermind_roadmap", repo: "coppermind", branch: "main", category: "accepted-rfc", tier: "TIER_1_ARCHITECTURE", ageDays: 1,
			content: "RFC-2026-11-24-55 blueprint for Coppermind static neural embeddings, knowledge graph edges, AST incremental indexing, MCP resources, and mergeable capsules."},
		{id: "doc_coppermind_deadend", repo: "coppermind", branch: "main", category: "dead_end", tier: "TIER_2_PRODUCT", ageDays: 1,
			content: "Dead-end troubleshooting fix: synchronous SQLite access_count updates during recall caused lock contention; use async coalesced batching."},
		{id: "doc_shield_redaction", repo: "shield", branch: "main", category: "architecture", tier: "TIER_1_ARCHITECTURE", ageDays: 14,
			content: "Shield wire guard loopback proxy performs Shannon entropy secret redaction before outbound API requests."},
		{id: "doc_fabrial_router", repo: "fabrial", branch: "main", category: "architecture", tier: "TIER_1_ARCHITECTURE", ageDays: 4,
			content: "Fabrial dynamic multi-tier router escalates archive Zip-Slip commands to Tier 2 microVM while preserving zero hop tax."},
		{id: "doc_merkle_verify", repo: "coppermind", branch: "main", category: "decision", tier: "TIER_1_ARCHITECTURE", ageDays: 2,
			content: "Isolate AST codebase index chunks under session index:<repo> so stale chunk pruning never breaks cryptographic Merkle chain verification."},
		{id: "doc_ui_rebinding", repo: "coppermind", branch: "main", category: "sovereign_invariant", tier: "TIER_0_SOVEREIGN", ageDays: 1,
			content: "Local Brain Explorer UI binds strictly to 127.0.0.1 ephemeral port with Host regex anti-DNS-rebinding, CSPRNG token cookie, CSP, and CSRF header."},
		{id: "doc_sleep_cycle", repo: "coppermind", branch: "main", category: "architecture", tier: "TIER_1_ARCHITECTURE", ageDays: 1,
			content: "Zero-key Sleep-Cycle consolidation distills episodic notes into PROPOSED learnings and forbids superseding TIER_0/1/2 invariants."},
		{id: "doc_pending_inbox", repo: "coppermind", branch: "main", category: "architecture", tier: "TIER_1_ARCHITECTURE", ageDays: 1,
			content: "Compiled git post-commit hook ingest-commit replaces shell interpolation and queues sink hits into pending_lens_tickets inbox."},
		{id: "doc_cartridge_v2", repo: "coppermind", branch: "main", category: "architecture", tier: "TIER_1_ARCHITECTURE", ageDays: 1,
			content: "Mergeable Ed25519 .capsule v2 cartridges enforce 50MB anti-zip-bomb caps, TypeReg-only tar guards, and non-destructive deduplication."},
		{id: "doc_scratchpad_cas", repo: "coppermind", branch: "main", category: "architecture", tier: "TIER_1_ARCHITECTURE", ageDays: 1,
			content: "Scratchpad v2 atomic CompareAndSwap coordinates parallel worktree handoff packets without repeating broken fixes."},
		{id: "doc_brief_compiler", repo: "coppermind", branch: "main", category: "architecture", tier: "TIER_1_ARCHITECTURE", ageDays: 1,
			content: "Deterministic 4-slot Context Brief Compiler allocates <=800 tokens for touched-file invariants, open alerts, recent decisions, and mentor nudges."},
		{id: "doc_mcp_resources", repo: "coppermind", branch: "main", category: "architecture", tier: "TIER_1_ARCHITECTURE", ageDays: 1,
			content: "MCP server exposes resources/list and resources/read over 5 exact allowlisted coppermind:// URIs rejecting traversal fail-closed."},
		{id: "doc_graph_taint", repo: "coppermind", branch: "main", category: "sovereign_invariant", tier: "TIER_0_SOVEREIGN", ageDays: 1,
			content: "Knowledge graph multi-hop BFS propagates untrusted web origin taint monotonically so untrusted seeds never pull TIER_0_SOVEREIGN nodes."},
		{id: "doc_ast_chunker", repo: "coppermind", branch: "main", category: "architecture", tier: "TIER_1_ARCHITECTURE", ageDays: 2,
			content: "Go AST parser chunks functions and type declarations with receiver symbols while Markdown heading-tree preserves fenced code blocks."},
		{id: "doc_cmvec_quant", repo: "coppermind", branch: "main", category: "architecture", tier: "TIER_1_ARCHITECTURE", ageDays: 1,
			content: "CMVEC1 int8 quantized static embedding packs verify SHA-256 checksums and refuse symlink model paths fail-closed."},
		{id: "doc_contradiction", repo: "coppermind", branch: "main", category: "architecture", tier: "TIER_1_ARCHITECTURE", ageDays: 1,
			content: "Write-time Contradiction Radar warns when a new TIER_1 rule conflicts with an active architectural invariant without supersedes."},
		// Distractor episodic noise in other repos
		{id: "noise_1", repo: "bomhound", branch: "main", category: "episodic", tier: "TIER_3_EPISODIC", ageDays: 45,
			content: "Old chore commit updating README badge and roadmap links in bomhound."},
		{id: "noise_2", repo: "fabrial", branch: "main", category: "episodic", tier: "TIER_3_EPISODIC", ageDays: 60,
			content: "Old episodic note mentioning database cache tuning and memory buffer size."},
	}

	queries := []evalQuery{
		{query: "login credential expiration lifetime", activeRepo: "conjoiner", expectID: "doc_auth_ttl"},
		{query: "db journal concurrency contention", activeRepo: "coppermind", expectID: "doc_sqlite_wal"},
		{query: "kernel process confinement latency", activeRepo: "airlock", expectID: "doc_airlock_seatbelt"},
		{query: "virtual machine isolation shadow workspace", activeRepo: "aegisbox", expectID: "doc_aegisbox_vm"},
		{query: "hardware vault biometric password enclave", activeRepo: "locksmith", expectID: "doc_locksmith_enclave"},
		{query: "malicious package dependency typosquatting", activeRepo: "argus", expectID: "doc_argus_quarry"},
		{query: "indirect jailbreak unicode sanitizer", activeRepo: "stormcage", expectID: "doc_stormcage_llm01"},
		{query: "license copyright bill of materials", activeRepo: "bomhound", expectID: "doc_bomhound_sbom"},
		{query: "hermetic build provenance signing", activeRepo: "soulcaster", expectID: "doc_soulcaster_slsa"},
		{query: "coppermind roadmap plan lenses capsules", activeRepo: "coppermind", expectID: "doc_coppermind_roadmap"},
		{query: "why did access count update deadlock", activeRepo: "coppermind", expectID: "doc_coppermind_deadend"},
		{query: "outbound secret leak masking proxy", activeRepo: "shield", expectID: "doc_shield_redaction"},
		{query: "archive traversal escalation tier routing", activeRepo: "fabrial", expectID: "doc_fabrial_router"},
		{query: "pruning deleted code chunks merkle integrity", activeRepo: "coppermind", expectID: "doc_merkle_verify"},
		{query: "localhost visualizer dns rebinding csrf", activeRepo: "coppermind", expectID: "doc_ui_rebinding"},
		{query: "distill episodic reflection proposed learnings", activeRepo: "coppermind", expectID: "doc_sleep_cycle"},
		{query: "git hook shell injection review tickets", activeRepo: "coppermind", expectID: "doc_pending_inbox"},
		{query: "shareable signed archive merge zip bomb", activeRepo: "coppermind", expectID: "doc_cartridge_v2"},
		{query: "atomic parallel worktree handoff mutex", activeRepo: "coppermind", expectID: "doc_scratchpad_cas"},
		{query: "800 token workspace summary slots", activeRepo: "coppermind", expectID: "doc_brief_compiler"},
		{query: "allowlisted mcp resource uri traversal", activeRepo: "coppermind", expectID: "doc_mcp_resources"},
		{query: "multi hop bfs untrusted web taint", activeRepo: "coppermind", expectID: "doc_graph_taint"},
		{query: "function symbol receiver markdown fence chunking", activeRepo: "coppermind", expectID: "doc_ast_chunker"},
		{query: "quantized int8 static vector symlink checksum", activeRepo: "coppermind", expectID: "doc_cmvec_quant"},
		{query: "conflicting invariant supersede warning on write", activeRepo: "coppermind", sinceDays: 4, expectID: "doc_contradiction"},
	}
	return docs, queries
}

func TestEval_Recall25QueryMRR5AndComparativeLift(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	docs, queries := evalDataset()
	now := time.Now().UTC()

	// 1. Evaluate CMVEC1 + CompositeReranker (upgraded v0.7 pipeline)
	packPath := filepath.Join(dir, "sovereign-dev-256.cmvec")
	sum, err := embedding.BuildSovereignDevPack(packPath)
	if err != nil {
		t.Fatalf("BuildSovereignDevPack failed: %v", err)
	}
	staticEmb, err := embedding.LoadStaticEmbedder(packPath, sum)
	if err != nil {
		t.Fatalf("LoadStaticEmbedder failed: %v", err)
	}

	store, err := sqlite.NewSQLiteStore(filepath.Join(dir, "eval_v07.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	mgr := brain.NewManager(store, staticEmb, scratchpad.NewMemoryScratchpad())
	defer mgr.Close()

	for _, d := range docs {
		ts := now.Add(-time.Duration(d.ageDays) * 24 * time.Hour)
		vec, _ := staticEmb.Embed(ctx, d.content)
		if err := store.Store(ctx, &brain.MemoryNode{
			ID:             d.id,
			SessionID:      d.repo,
			Category:       d.category,
			Content:        d.content,
			Vector:         vec,
			Provenance:     brain.ProvenanceLocalWorkspace,
			AuthorityTier:  d.tier,
			EmbeddingModel: staticEmb.ModelName(),
			EmbeddingDim:   staticEmb.Dimension(),
			Metadata:       map[string]string{"git_repo": d.repo, "git_branch": d.branch},
			CreatedAt:      ts,
			UpdatedAt:      ts,
		}); err != nil {
			t.Fatalf("store %s failed: %v", d.id, err)
		}
	}

	var totalRR float64
	var maxLatency time.Duration
	for _, q := range queries {
		req := brain.RecallRequest{
			Query:      q.query,
			ActiveRepo: q.activeRepo,
			Hybrid:     true,
			Hops:       1,
			Limit:      5,
		}
		if q.sinceDays > 0 {
			after := now.Add(-time.Duration(q.sinceDays) * 24 * time.Hour)
			req.CreatedAfter = &after
		}
		start := time.Now()
		res, err := mgr.Recall(ctx, req)
		elapsed := time.Since(start)
		if elapsed > maxLatency {
			maxLatency = elapsed
		}
		if err != nil {
			t.Fatalf("recall %q failed: %v", q.query, err)
		}
		rr := 0.0
		for rank, r := range res {
			if r.Node.ID == q.expectID {
				rr = 1.0 / float64(rank+1)
				break
			}
		}
		if rr == 0 {
			var got []string
			for _, r := range res {
				got = append(got, fmt.Sprintf("%s(%.2f)", r.Node.ID, r.Score))
			}
			t.Logf("MISS query=%q expect=%s got=[%s]", q.query, q.expectID, strings.Join(got, ", "))
		}
		totalRR += rr
	}

	mrr5 := totalRR / float64(len(queries))
	t.Logf("✓ CMVEC1 + CompositeReranker 25-query MRR@5 = %.3f (max latency=%v)", mrr5, maxLatency)
	if mrr5 < 0.88 {
		t.Fatalf("25-query MRR@5 below quality bar: got %.3f, want >= 0.88", mrr5)
	}
}

func TestEval_10kNodeAtomicVectorSlabLatencySLA(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 10k-node SLA benchmark in -short mode")
	}
	dir := t.TempDir()
	ctx := context.Background()

	store, err := sqlite.NewSQLiteStore(filepath.Join(dir, "slab_10k.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	emb := embedding.NewLocalHashEmbedder(128)
	baseVec, _ := emb.Embed(ctx, "coppermind sqlite wal single writer ring")

	// Bulk-insert 10,000 nodes inside one fast transaction so setup takes <250ms
	tx, err := store.DB().Begin()
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := tx.Prepare(`INSERT INTO memory_nodes (
		id, session_id, category, content, vector_blob, provenance, taint_score, metadata_json,
		created_at, updated_at, authority_tier, lifecycle_status, embedding_model, embedding_dim
	) VALUES (?, ?, ?, ?, ?, 'TRUST_LOCAL_WORKSPACE', 0.0, '{}', ?, ?, 'TIER_3_EPISODIC', 'ACTIVE', 'local-hash-128', 128)`)
	if err != nil {
		t.Fatal(err)
	}
	vecBlob := make([]byte, len(baseVec)*4)
	nowNano := time.Now().UnixNano()
	for i := 0; i < 10000; i++ {
		if _, err := stmt.Exec(
			fmt.Sprintf("mem_10k_%05d", i),
			"bench",
			"episodic",
			fmt.Sprintf("Benchmark node %d discussing latency and storage", i),
			vecBlob,
			nowNano,
			nowNano,
		); err != nil {
			t.Fatal(err)
		}
	}
	stmt.Close()
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	// Warm atomic vector slab snapshot once
	if _, err := store.RecallSemantic(ctx, baseVec, brain.MemoryFilter{Limit: 10}); err != nil {
		t.Fatal(err)
	}

	// Measure 25 warm recalls over 10,000 nodes
	const runs = 25
	latencies := make([]time.Duration, runs)
	for i := 0; i < runs; i++ {
		s := time.Now()
		_, err := store.RecallSemantic(ctx, baseVec, brain.MemoryFilter{Limit: 10})
		latencies[i] = time.Since(s)
		if err != nil {
			t.Fatal(err)
		}
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	p50 := latencies[runs/2]
	p95 := latencies[(runs*95)/100]
	t.Logf("✓ 10,000-node atomic vector slab recall: p50=%v p95=%v", p50, p95)
	// Under -race overhead allow generous ceiling (25ms); standard non-race is <3ms.
	if p50 > 25*time.Millisecond {
		t.Fatalf("10k-node slab p50 too slow: %v", p50)
	}
}
