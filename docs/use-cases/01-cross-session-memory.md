# Recipe: Cross-Session Persistent Memory & Retrieval

> **Use Case ID:** `COP-UC-01`  
> **Target Audience:** Developers, Agent Builders, Knowledge Engineers  
> **Platform Engine:** Pure-Go SQLite WAL & Hybrid BM25/Cosine Vector Search  

---

## 1. Problem Statement

Autonomous coding agents (Cursor, Claude Code, Antigravity) are stateless: every new session starts from scratch. Conventions established in previous sessions, subtle bug workarounds, and architectural decisions are forgotten, forcing developers to re-explain project context repeatedly.

---

## 2. When to Use This

Use **Coppermind** to give agents persistent, project-scoped memory. Coppermind runs locally, embedding facts into an in-process SQLite database. Agents recall past context using semantic queries (`coppermind recall`) or persist new discoveries (`coppermind remember`).

---

## 3. Architecture & Dataflow

```mermaid
flowchart LR
    Dev["Developer / Agent: 'coppermind remember --content \"...\"'"] --> DB["🧠 Coppermind In-Memory / WAL Database"]
    
    DB --> Index["Hybrid Indexing<br/>• BM25 Full-Text Keywords<br/>• Local Cosine Vector Embeddings"]
    
    Query["Agent Query: 'coppermind recall \"how do we test auth?\"'"] --> Search["Hybrid BM25 + Vector Ranker"]
    
    Search --> Results["Ranked Memory Snippets with Trust Tiers"]
```

---

## 4. Prerequisites

1. **Coppermind Installed:** `brew install bonjoski/tap/coppermind` (or built from source).

---

## 5. Step-by-Step Recipe

### Step 1: Store an Architectural Fact
```bash
coppermind remember \
  --category architecture \
  --content "All database queries in this service must use prepared statements to prevent SQL injection."
```

### Step 2: Query Context via Semantic Search
```bash
coppermind recall "database query standards"
```
Expected output:
```text
Found 1 relevant memory in project vault "active":
1. [Score: 0.89] [TIER_1_ARCHITECTURE | TRUST_LOCAL_WORKSPACE]
   All database queries in this service must use prepared statements to prevent SQL injection.
```

### Step 3: Switch Project Vaults
```bash
# Isolate memories by project (e.g. personal vs work vs open-source)
coppermind project use personal
```

---

## 6. Verification & Expected Output

Verify database health and total stored facts:
```bash
coppermind status
```
Outputs total memories, active scratchpad keys, and index health.

---

## 7. Security Invariants & Blast Radius

- **100% Local Storage:** The SQLite database resides at `~/.coppermind/projects/<project>/coppermind.db`. Zero embeddings or facts leave the host machine.
- **Provenance Tiers:** Memories are labeled with trust provenance (`TRUST_LOCAL_WORKSPACE` vs `TAINT_UNTRUSTED_WEB`).

---

## 8. Troubleshooting & Common Pitfalls

- **Issue:** Search returns low scores for exact function names.  
  **Remediation:** Coppermind supports hybrid BM25 search; prefix exact names with quotes: `coppermind recall '"ExecuteQuery"'`.
