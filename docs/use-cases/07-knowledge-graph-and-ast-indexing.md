# Use Case 07: Lightweight Knowledge Graph & Incremental AST Codebase Indexing

> **Target:** Multi-hop structural impact analysis (`pkg/mcp/server.go` → invariants, ADRs, bugs) and sub-second incremental AST indexing without index rot or Merkle chain breaks.

## Scenario
You are editing a security-critical file and want to instantly see every architectural invariant, RFC decision, past bug, and code symbol linked to it—while keeping your indexed codebase fresh on every edit without accumulating duplicate stale chunks.

## Recipe

```bash
# 1. Incrementally index a repository using Go AST + Markdown heading-tree chunking
coppermind index .

# 2. Re-running skips unchanged files via SHA-256 and automatically prunes deleted/modified chunks
coppermind index .

# 3. Inspect every active invariant, decision, and chunk linked to a specific file
coppermind graph impact pkg/mcp/server.go

# 4. Traverse 1-2 hop graph neighbors from any memory node
coppermind graph neighbors mem_a1b2c3d4 --hops 2

# 5. Run multi-hop Graph-RAG directly in recall
coppermind recall --hops 2 "MCP resource URI confinement"
```

## Security & Integrity Guarantees
- **Merkle Chain Isolation:** Code-index chunks live in `session_id="index:<repo>"`, so pruning stale chunks never breaks `coppermind verify` on conversational or commit episodic chains.
- **Symlink Confinement:** `os.OpenRoot` + `os.Lstat` refuse symlink escapes fail-closed (e.g., `evil.go -> ~/.ssh/id_rsa`).
- **Hub-Node & Taint Isolation:** Extraction is capped at `32` edges/node, BFS is hard-clamped to `<=2` hops / `<=50` nodes, and untrusted web seeds can never transitively pull `TIER_0_SOVEREIGN` nodes.
