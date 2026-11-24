# Use Case 08: `<8ms` Context Briefs, MCP Resources, Pending Commit Inbox & Zero-Key Sleep Cycle

> **Target:** Proactive agent grounding via native MCP `resources/*` and zero-API-key continuous review + memory consolidation.

## Scenario
Instead of manually querying Coppermind at the start of every session—or letting git hooks silently drop background LLM calls when Ollama isn't running—you want an instant `<=800`-token workspace brief, a local Pending Lens Inbox fed by safe compiled git hooks, and a zero-key Sleep Cycle that distills noisy episodic trails into crisp learnings.

## Recipe

```bash
# 1. Compile a deterministic <=800-token brief for your current repo, branch & dirty files
coppermind brief
coppermind brief --format json

# 2. Install the compiled, shell-injection-free git post-commit & post-merge hooks
coppermind hook install

# 3. Inspect commits queued by zero-cost lens pre-filters
coppermind inbox list

# 4. In your IDE (Claude Code, Cursor, Antigravity, Codex):
#    • Attach MCP resource `coppermind://brief/current` or `coppermind://inbox/pending`
#    • Pop and evaluate the oldest pending commit with 0 extra API keys:
#      coppermind_lens_prepare(lens="security-architect", from_inbox=true) -> coppermind_lens_submit
#    • Run Sleep-Cycle memory consolidation:
#      /coppermind:consolidate  (or coppermind_consolidate_prepare -> coppermind_consolidate_submit)
```

## Security Guarantees
- **Zero Shell Interpolation:** `post-commit` delegates directly to compiled `coppermind hook ingest-commit` using Go `exec.Command`, neutralizing commit-message command injection (`$(...)`).
- **Exact Allowlisted MCP URIs:** `resources/read` rejects path traversal and non-allowlisted URIs fail-closed.
- **Immutable High-Authority Tiers:** Sleep-Cycle consolidation writes strictly as `TIER_3_DERIVED` / `PROPOSED` and fails closed on any attempt to supersede `TIER_0_SOVEREIGN`, `TIER_1_ARCHITECTURE`, or `TIER_2_PRODUCT` nodes.
