# 🧭 Use Case 03: Product Owner Abuse-Case Acceptance Criteria (`requirements` Lens)

> **Scenario:** You are a Product Owner, Tech Lead, or developer drafting a user story or PRD—for either a traditional web/API feature or a new AI/RAG/MCP feature—and want 2–3 plain-English, sprint-ready `Given / When / Then` safety acceptance criteria in under 30 seconds without 60-question security forms or security jargon.  
> **Runtime Scope:** 100% local single-workstation CLI & MCP (`COPPERMIND_PROFILE=local`, ephemeral read-only matching, zero cloud GRC SaaS or fleet telemetry).  
> **Latency & Budget:** `< 5ms` local lookup, max 3 criteria, `<= 180` tokens total in default mode, zero episodic persistence of pasted PRDs or user stories.

---

## Why Shift Left of the First Prompt?

User stories naturally describe the **happy path** (*"As a support agent, I want an AI assistant to summarize tickets and issue refunds up to $50"*). When security boundaries are discovered only during PR review or pre-release checks, architecture fixes cost 10x more and threaten sprint commitments.

The **Phase 0 Paved Road** pairs two lightweight open-source primitives:
1. **The 5-Question Plain-English Blast-Radius Trigger Card** (embedded in GitHub Issue and PRD templates): 5 binary checkboxes replace 60-question questionnaires. **Zero checked boxes = zero security ceremony.**
2. **Coppermind `requirements` Lens:** Maps checked triggers and/or pasted story text deterministically to at most 3 jargon-free `Given / When / Then` safety acceptance criteria, each linked directly to a local verification command (`aegisbox`, `argus`, `locksmith`, `bomhound`, or `soulcaster`).

---

## The 5-Question Plain-English Blast-Radius Triggers

| Question | Plain-English Check | Trigger Flag |
| :--- | :--- | :--- |
| **Q1** | Does this touch login, permissions, billing/money, or cross-customer data? | `auth_data_money` |
| **Q2** | Does this send text to an AI model or search documents for AI context (RAG)? | `ai_rag_context` |
| **Q3** | Can an AI call a tool/API that changes state (write, delete, refund, email, webhook)? | `ai_state_mutation` |
| **Q4** | Does this add a new third-party library, external API, or MCP tool server? | `supply_chain_mcp` |
| **Q5** | Does this store, log, or send API keys, passwords, or sensitive customer PII? | `secrets_pii` |

* **0 boxes checked:** Fast-track straight to development — zero security ceremony.
* **1+ boxes checked:** Run `coppermind requirements` locally and paste the 2–3 generated criteria into the ticket before sprint sizing.

---

## Real Before & After User Stories

### Example 1: AI Support Assistant with Ticket Search & Refunds (Q2 + Q3)

**Before (Happy-Path Only):**
> As a support agent, I want an AI assistant to summarize customer tickets and issue refunds up to $50 so we resolve routine billing issues faster.

**Run Locally (Zero-Config, `< 5ms`, Ephemeral):**
```bash
coppermind requirements \
  --story "As a support agent, I want an AI assistant to summarize customer tickets and issue refunds up to $50" \
  --triggers ai_rag_context,ai_state_mutation
```

**After (Ready to Paste Into GitHub, Jira, or Linear):**
```markdown
### Safety Acceptance Criteria
1. **Isolate AI Search by Tenant**
  - **Given** Customer A queries past tickets,
  - **When** search fetches AI context,
  - **Then** DB filters tenant_id = A before model call.
  - *Verify:* `aegisbox test --ai-safety --rag`
2. **Enforce AI Action Caps in Code**
  - **Given** a ticket asks for a $500 refund,
  - **When** the AI calls the refund tool,
  - **Then** server code enforces the $50 cap.
  - *Verify:* `aegisbox test --ai-safety --tools`
```

Need a 1-sentence business-impact explanation for stakeholders or a hands-on developer kata link? Add `--why`:
```bash
coppermind requirements \
  --story "As a support agent, I want an AI assistant to summarize customer tickets and issue refunds up to $50" \
  --triggers ai_rag_context,ai_state_mutation \
  --why
```

---

### Example 2: Deterministic Web / Billing Feature (Q1 + Q5)

**Before (Happy-Path Only):**
> As an account admin, I want to download customer invoices and apply promo discounts from the billing dashboard.

**Run Locally:**
```bash
coppermind requirements \
  --story "Allow account admins to download customer invoices and apply promo discounts from the billing dashboard" \
  --triggers auth_data_money,secrets_pii
```

**After:**
```markdown
### Safety Acceptance Criteria
1. **Block Cross-Customer Access**
  - **Given** User A requests User B's record ID,
  - **When** the API reads or updates it,
  - **Then** session ownership check denies it (403).
  - *Verify:* `aegisbox test --authz`
2. **Enforce Prices Server-Side**
  - **Given** a client alters price or discount,
  - **When** checkout or refund runs,
  - **Then** server recalculates from trusted records.
  - *Verify:* `aegisbox test --billing`
3. **Scrub Customer PII from Logs**
  - **Given** a request has emails or cards,
  - **When** logs or errors are written,
  - **Then** sensitive fields redact before storage.
  - *Verify:* `bomhound check`
```

---

## Reading From Local PRDs & IDE MCP Usage

### From a Local PRD Markdown File (`--story-file`, Strict 256KB Cap)
```bash
# Emit calm Markdown directly from a local PRD file
coppermind requirements --story-file ./docs/prd-refund-assistant.md

# Emit machine-readable JSON for local helper scripts
coppermind requirements --story-file ./docs/prd-refund-assistant.md --json
```

### Over MCP (`coppermind_recall` with `lens="requirements"`)
Your local IDE assistant (Cursor, Claude Code, Antigravity) can generate sprint-ready safety acceptance criteria directly from a story draft without persisting story text to episodic memory:

```json
{
  "name": "coppermind_recall",
  "arguments": {
    "lens": "requirements",
    "query": "As a support agent, I want an AI assistant to summarize customer tickets and issue refunds up to $50",
    "triggers": ["ai_rag_context", "ai_state_mutation"],
    "limit": 3
  }
}
```

### Importing Custom Team Requirements Capsules
Out of the box, `coppermind requirements` uses the embedded 10-card curated starter pack (`capsules/po-abuse-case-criteria.mentor.json`). You can also verify and import custom local requirements capsules into SQLite WAL:
```bash
coppermind capsule verify --allow-unsigned capsules/po-abuse-case-criteria.mentor.json
coppermind capsule import --allow-unsigned capsules/po-abuse-case-criteria.mentor.json
```

---

## Requirements-to-Test Traceability

Every generated acceptance criterion carries an allowlisted local `verify_cmd` so POs and developers share an objective **Definition of Done**:

| Trigger Domain | Local Verification Command | What It Proves |
| :--- | :--- | :--- |
| **Q1 (Auth / Data / Money)** | `aegisbox test --authz` / `aegisbox test --billing` | Cross-tenant ownership and server-side price/limit enforcement |
| **Q2 (AI / RAG Context)** | `aegisbox test --ai-safety --rag` | Tenant-filtered retrieval and untrusted-text instruction fencing |
| **Q3 (AI State Mutation)** | `aegisbox test --ai-safety --tools` | Deterministic code limits and confirmation on risky AI tool actions |
| **Q4 (Supply Chain / MCP)** | `argus vet --diff` / `soulcaster verify-patch` | Typosquat vetting and pinned MCP/dependency provenance |
| **Q5 (Secrets / PII)** | `locksmith run -- env` / `bomhound check` | Runtime-only secret injection and PII/license hygiene |

---

## Privacy & Security Invariants

* **Zero Story Echo (OWASP LLM01 Defense):** Untrusted customer requests or hostile PRD text are NFKC-normalized in memory for matching only and are **never** interpolated into `Given`, `When`, `Then`, or `Verify` output fields.
* **Ephemeral & Read-Only:** Raw story text and PRD files are **never** persisted into Coppermind's SQLite episodic memory tables, protecting any pasted customer PII or internal roadmap text.
* **Fail-Closed Capsule Quarantine:** Imported requirements capsules reject raw HTML/XSS markup (`<script`, `<img`, `<iframe`, `javascript:`), control/ANSI escapes, leaked secrets, authority tier escalation, and any `verify_cmd` containing shell chaining metacharacters or verbs outside `{aegisbox, argus, locksmith, bomhound, soulcaster, fabrial, airlock}`.
* **100% Local Developer Scope:** Runs strictly on the local workstation with static open-source Markdown templates; zero cloud GRC SaaS or centralized fleet governance.
