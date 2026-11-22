# 🛡️ Use Case 02: Security Mentor Capsules for AI & Web Apps

> **Scenario:** You are building a web API, RAG pipeline, or MCP tool server with an AI coding assistant (Cursor, Claude Code, Antigravity) and want concise, plain-English security architecture defaults surfaced **before** code is written—without cloud SaaS dependencies, blocking gates, or bloated checklists.  
> **Runtime Scope:** 100% local developer workstation (`COPPERMIND_PROFILE=local`, pure-Go SQLite WAL).  
> **Latency & Budget:** `< 5ms` lock-free WAL recall, max 2 cards per query, `<= 120` tokens per nudge.

---

## Why Security Mentor Capsules?

Developers who instinctively parameterize SQL queries often hit unfamiliar failure modes when integrating LLMs, RAG vector stores, and MCP tools:
* Concatenating untrusted tickets or documents into system prompts (**Indirect Prompt Injection**).
* Filtering multi-tenant RAG chunks inside prompt prose instead of the database `WHERE` clause.
* Relying on *"please don't delete prod"* prompt instructions instead of deterministic middleware authorization.
* Leaving `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` in plaintext `.env` files.

**Security Mentor Capsules** package compact, versioned mental models (`TIER_2_MENTOR_CAPSULE`) directly into your local Coppermind SQLite vault. Your coding assistant recalls at most 2 relevant defaults during ideation and applies them on the first try.

---

## Zero-Config Local Quickstart (Out of the Box)

All **3 curated v1.0 mentor packs (18 cards)** plus the **10 PO abuse-case criteria** are embedded directly into the `coppermind` binary via `//go:embed`. On a brand-new workstation with an empty local SQLite vault, passive ideation nudges work **immediately with zero setup**:

### 1. Run Passive Mentor Recall Immediately (`< 5ms`, `<= 120` tokens/nudge)

```bash
# Works zero-config out of the box — no manual import required!
coppermind recall --lens mentor "add a RAG support ticket search and refund MCP tool"

# Include optional detected SDK hints
coppermind recall --lens mentor --sdk openai,pgvector "store customer docs for vector search"
```

Example output:
```text
[ai-rag-01-prompt-data-fence | TIER_2_MENTOR_CAPSULE | ai-app-and-rag-safety@1.0.0#...]
Default: Wrap untrusted user inputs and RAG chunks inside explicit <untrusted_context> delimiters via stormcage with a strict data-only instruction.
Why: Untrusted tickets, web pages, or PDFs concatenated into prompts can hijack the model into leaking data or invoking tools.
Analogy: SQLi parameterization: never concatenate untrusted text directly into executable instructions.
Kata: `aegisbox learn kata-03-rag-injection`
```

### 2. Drop In the 10-Second IDE Starter Snippet
Copy the relevant snippet from [`starter-pack/`](../../starter-pack/) into your repo or personal workspace rules:
* [`starter-pack/AGENTS.md.snippet`](../../starter-pack/AGENTS.md.snippet) — Antigravity / Codex / generic agent repos
* [`starter-pack/.cursorrules.snippet`](../../starter-pack/.cursorrules.snippet) — Cursor
* [`starter-pack/CLAUDE.md.snippet`](../../starter-pack/CLAUDE.md.snippet) — Claude Code

Over MCP, your assistant calls `coppermind_recall` with `lens="mentor"` (which also falls back automatically to the 18 embedded defaults until custom capsules are imported):
```json
{
  "name": "coppermind_recall",
  "arguments": {
    "lens": "mentor",
    "query": "add a refund MCP tool",
    "detected_sdks": ["mcp"],
    "limit": 2
  }
}
```

---

## Cryptographic Capsule Signing, Packing & Verification (`TRUST_SIGNED_CAPSULE`)

Every `capsule import` runs through Coppermind's **Two-Gate Import Quarantine**:
1. **Merkle Root + Ed25519 Signature Verification** (signed `.capsule` archives import cleanly as `TRUST_SIGNED_CAPSULE` without `--allow-unsigned`; unsigned drafts require `--allow-unsigned` and are tagged `TAINT_UNVERIFIED_DRAFT`).
2. **Cognitive Firewall + Secret Quarantine** (NFKC + homoglyph smuggling scan, OWASP LLM01 injection defense, secret redaction/rejection, and `TIER_2_MENTOR_CAPSULE` authority lock).

Both **Mentor** (`bonjoski-mentor-v1`) and **Requirements** (`bonjoski-requirements-v1`) manifests are supported:

```bash
# 1. Generate a local Ed25519 signing keypair (atomic 0600 private key; refuses symlinks and accidental overwrites)
coppermind capsule keygen --out ~/.coppermind/keys

# 2. Sign and pack a Mentor or Requirements manifest into a verifiable .capsule (tar.gz) archive
coppermind capsule sign \
  --in capsules/ai-app-and-rag-safety.mentor.json \
  --key ~/.coppermind/keys/ed25519.key \
  --out dist/ai-app-and-rag-safety.capsule

# (Optional) Pack a pre-signed JSON manifest into a .capsule archive
coppermind capsule pack --in dist/ai-app-and-rag-safety.signed.json --out dist/ai-app-and-rag-safety.capsule

# 3. Verify offline against the public key file (rejects any 1-byte tamper fail-closed)
coppermind capsule verify --pubkey ~/.coppermind/keys/ed25519.pub dist/ai-app-and-rag-safety.capsule

# 4. Import WITHOUT --allow-unsigned as TRUST_SIGNED_CAPSULE
coppermind capsule import --pubkey ~/.coppermind/keys/ed25519.pub dist/ai-app-and-rag-safety.capsule
coppermind capsule list
```

---

## Closed Production-to-Ideation Flywheel (`coppermind distill`)

Turn any staging or production near-miss into three reusable, strictly quarantined artifacts in seconds—feeding lessons directly back into Phase 0 (PO criteria), Phase 1 (Mentor nudges), and local PR regression testing (`aegisbox test --ai-safety --probes-file`):

```bash
# Option A: Distill from a sanitized lesson-to-capsule.md file (strict 256KB cap)
coppermind distill --from-file ./lesson-to-capsule.md --out-dir ./distilled

# Option B: Distill directly from structured CLI flags
coppermind distill \
  --id ai-tool-07-negative-refund-cap \
  --domain mcp-tools \
  --title "Reject Negative Refund Arguments" \
  --pattern "An LLM tool handler checked amount <= 5000 without enforcing amount >= 0." \
  --analogy "Like missing unsigned bounds checks in server-side billing code." \
  --fix "Reject req.AmountCents < 0 fail-closed in deterministic middleware before calling the refund handler." \
  --why "Prompt-injected negative refunds can credit attacker accounts instead of debiting them." \
  --triggers "refund,mcp,tool arguments" \
  --verify-cmd "aegisbox test --ai-safety --categories mcp_scope_escalation" \
  --probe-payload '{"order_id":"ord_demo","amount_cents":-5000}' \
  --out-dir ./distilled
```

This emits three validated JSON files inside `./distilled`:
1. `<id>.mentor-card.json` — Validated `MentorCard` (`secure_default <= 180` chars, `why_one_liner <= 200` chars).
2. `<id>.abuse-case.json` — Validated `AbuseCaseCriterion` (`Given / When / Then` + allowlisted `verify_cmd`).
3. `<id>.aegisbox-probe.json` — Custom probe stub (`probe_id`, `category`, `payload`, `expected_signal`, `fix_patch_hint`, `why_one_liner`) compatible with `aegisbox test --ai-safety --probes-file`.

**Fail-Closed Quarantine Gate:** Every field (and raw markdown file) is scanned through Coppermind's cognitive firewall (OWASP LLM01, NFKC/homoglyph, HTML/XSS rejection), Shannon-entropy & credential regex secret quarantine, strict `verify_cmd` verb allowlisting, and RFC1918 (`10.*`, `192.168.*`, `172.16-31.*`) + private domain (`.corp`, `.internal`) leak detection—aborting fail-closed with zero canary bytes leaked.

---

## Safety & Epistemic Invariants

* **Zero Authority Escalation:** Mentor cards are hard-locked to `TIER_2_MENTOR_CAPSULE`. Any manifest or card attempting to claim `TIER_0_SOVEREIGN`, `TIER_0_INVARIANT`, or `TIER_1_ARCHITECTURE` is rejected fail-closed at import time.
* **Bounded Context Budget:** `secure_default <= 180 chars`, `why_one_liner <= 200 chars`, max 2 cards per recall, `<= 120` tokens per nudge, max 5MB capsule archive (zip-bomb protected via `io.LimitReader`).
* **Multi-Agent Concurrency ($N=8$):** Imported mentor cards live in SQLite WAL tables (`mentor_capsules`, `mentor_cards`). Eight parallel agents read lock-free while writes serialize through Coppermind's single-writer ring channel.
* **100% Local Sovereign Scope:** Zero cloud SaaS, zero telemetry, zero corporate proxy. Everything runs locally on your workstation.
