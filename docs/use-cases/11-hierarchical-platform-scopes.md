# 🗂️ Use Case 11: Hierarchical Platform Scopes & Inherited Knowledge

> **RFC:** [`RFC-2026-11-24-58`](https://github.com/bonjoski/spanreed/blob/main/docs/plans/accepted/2026-11-24-coppermind-hierarchical-scopes-rfc.md)  
> **Profiles Supported:** Profile A (Local SQLite WAL) & Profile B (PostgreSQL 17 + `pgvector`)

---

## The Problem

Coppermind project vaults (`--project github`, `--project personal`) enforce strict 0% cross-contamination between unrelated domains. Inside a single platform or monorepo, however, you often need **layered context**:
- **General platform-wide guidance** (`platform`) — logging standards, auth envelopes, database invariants.
- **Domain-level rules** (`platform/payments`) — idempotency keys, ledger consistency.
- **Component-specific details** (`platform/payments/webhooks`) — Stripe raw-body HMAC verification, retry queues.
- **Zero noise from unrelated siblings** (`platform/auth`) when working on `platform/payments/webhooks`.

Hierarchical Scopes solve this inside a single project vault with zero extra database handles, zero wrapper hop tax, and native knowledge-graph links across levels.

---

## Quickstart Workflow

```bash
# 1. Store general platform guidance
coppermind --project acme remember --scope platform --category architecture \
  "All HTTP services must propagate X-Request-ID and emit structured JSON logs."

# 2. Store domain-level architecture rules
coppermind --project acme remember --scope platform/payments --category architecture \
  "All payment mutations require an Idempotency-Key header stored for 24h."

# 3. Store leaf-service specifics (and an unrelated sibling component)
coppermind --project acme remember --scope platform/payments/webhooks --category convention \
  "Verify Stripe-Signature over raw unparsed request bytes before JSON decoding."

coppermind --project acme remember --scope platform/auth --category architecture \
  "Rotate OIDC JWKS keys every 30 days."

# 4. Recall from the leaf component (default mode: ancestors)
#    Returns vault-global + platform + platform/payments + platform/payments/webhooks
#    Excludes platform/auth siblings, and boosts leaf specifics to the top!
coppermind --project acme recall --scope platform/payments/webhooks --explain \
  "How should webhook requests handle logging, idempotency, and signatures?"

# 5. Inspect the vault's scope tree or a scope's inheritance chain
coppermind --project acme scope list
coppermind --project acme scope show platform/payments/webhooks

# 6. Compile a <=800-token scoped context brief (<8ms)
coppermind --project acme brief --scope platform/payments/webhooks
```

---

## Recall Scope Modes (`--scope-mode`)

| Mode | Matches | Typical Use |
| :--- | :--- | :--- |
| `ancestors` *(default)* | `""` (vault-global) + all ancestors + exact scope | Day-to-day coding inside a component with inherited platform guardrails |
| `exact` | Only memories at the exact scope | Auditing or listing rules specific to one component |
| `subtree` | Exact scope + all descendants (`target/*`) | Reviewing or exporting a whole domain (`capsule export --scope platform/payments`) |
| `lineage` | `ancestors ∪ subtree` (excludes siblings) | Mid-level domain work needing both platform rules above and child specifics below |
| `all` | Entire vault (soft specificity boost only) | Cross-platform search while keeping your active scope ranked higher |

---

## Automatic Scoping with `.coppermind.yaml`

Check a declarative `.coppermind.yaml` into your monorepo root (strictly repo-confined via `os.OpenRoot`, non-symlink, `<=16 KiB`, allowlisted keys only):

```yaml
scope: platform
paths:
  services/payments: platform/payments
  services/payments/webhooks: platform/payments/webhooks
  services/auth: platform/auth
```

Resolution precedence: `--scope` flag / MCP `scope` → `COPPERMIND_SCOPE` env var → nearest `.coppermind.yaml` inside the git repo root → `""` (vault-global).

### Indexing, Vault Watching & Cartridges

```bash
# Index a monorepo using .coppermind.yaml path-to-scope rules
coppermind --project acme index --scope-from-config .

# Sync an Obsidian/ADR folder hierarchy into nested scopes automatically
coppermind --project acme watch --once --scope platform/docs --scope-from-dirs ./docs

# Export just the payments subtree as a signed .capsule v2 cartridge
coppermind --project acme capsule export --scope platform/payments --scope-mode subtree \
  --key ./keys/ed25519.key --out payments.capsule

# Mount an imported cartridge beneath a target scope prefix
coppermind --project acme capsule merge --pubkey ./keys/ed25519.pub \
  --scope-prefix legacy payments.capsule
```

---

## MCP & Brain Explorer Integration

- **MCP Tools:** `coppermind_remember` accepts `scope`; `coppermind_recall` accepts `scope` and `scope_mode`; `coppermind_lens_prepare` accepts `scope` so zero-key audits ground findings in ancestor platform invariants.
- **MCP Resource:** Read `coppermind://scopes/tree` to inspect all active scopes and invariant counts in one call.
- **Explorer (`tui` / `ui`):** Run `scopes` in `coppermind tui`, or query `GET /api/v1/scopes`, `GET /api/v1/search?q=...&scope=...`, and `GET /api/v1/timeline?scope=...` in `coppermind ui`.

---

## Security & Integrity Invariants

- **Fail-Closed Cross-Scope Supersession:** A child scope (`platform/payments/webhooks`) cannot supersede or tombstone a memory in a broader ancestor scope (`platform` or vault-global).
- **Backward-Compatible Merkle v2:** Legacy unscoped chains (`scope == ""`) keep identical v1 hashes; scoped nodes bind `scope` into a domain-separated v2 digest so direct SQL scope-escalation tampering is caught by `coppermind verify`.
- **Graph-RAG Sibling Isolation:** 1–2 hop knowledge graph expansion enforces the active scope predicate so shared code entities never leak sibling-branch context.
