# 💡 Coppermind End-User Use Cases & Recipes

> **Repository:** [`github.com/bonjoski/coppermind`](https://github.com/bonjoski/coppermind)  
> **Classification:** Developer Recipes & Task-Oriented Guides  
> **Source of Truth:** Authoritative Standard  

---

## Overview

**Coppermind** is a local-first AI memory system that gives your coding agents persistent, searchable, tamper-evident memory across sessions—with zero cloud dependencies. Built on pure-Go SQLite WAL mode (or optional PostgreSQL 17 + pgvector), local vector and BM25 hybrid search, a lightweight knowledge graph, and host-evaluated memory lenses, Coppermind keeps agent context durable without external SaaS.

This directory provides task-oriented recipes for common AI memory workflows.

---

## 📚 Recipe Catalog

| Recipe | Problem Addressed | Primary CLI Commands | Mechanism |
| :--- | :--- | :--- | :--- |
| **[01. Cross-Session Persistent Memory & Retrieval](01-cross-session-memory.md)** | Store project architectural conventions, debugging findings, and ADRs; query via hybrid vector search. | `coppermind remember`<br/>`coppermind recall "<query>"` | Pure-Go SQLite WAL + Vector Index |
| **[02. Security Mentor Capsules for AI & Web Apps](02-security-mentor-capsules-for-ai-apps.md)** | Import signed/verified open-source security mental-model packs and receive `<= 120`-token passive nudges during ideation. | `coppermind capsule import`<br/>`coppermind recall --lens mentor "<topic>"` | Mentor Lens + Two-Gate Import Quarantine |
| **[02b. Automated Post-Commit Episodic Reflection](02-git-hook-reflection.md)** | Automatically parse, sanitize, and ingest git commit diffs into episodic memory via git hooks. | `coppermind hook install`<br/>`coppermind observations` | Git Post-Commit Hook |
| **[03. Product Owner Abuse-Case Acceptance Criteria](03-product-owner-abuse-case-criteria.md)** | Turn 5-question plain-English blast-radius triggers and user stories into `<= 3` sprint-ready `Given / When / Then` safety acceptance criteria (`<= 180` tokens, ephemeral). | `coppermind requirements --story "..."`<br/>`coppermind recall --lens requirements` | Requirements Lens + Curated PO Capsule |
| **[03b. Multi-Perspective Analytical Threat Lenses](03-analytical-threat-lenses.md)** | Run automated multi-persona reviews (`security-architect`, `devils-advocate`, `red-team-operator`) on RFC proposals. | `coppermind radar`<br/>`coppermind proposals` | Memory Lenses Engine |
| **[03c. Zero-API-Key Host-Evaluated Lenses](03-zero-api-key-host-evaluated-lenses.md)** | Run security, systems, and drift audits on your active IDE AI subscription with deterministic Go PoC-gating, secret quarantine, and single-use HMAC `eval_token` handoff. | `/coppermind:security-audit`<br/>`coppermind_lens_prepare` → `coppermind_lens_submit` | MCP `prompts/*` + Host-Evaluated Lens Handoff |
| **[04. Exporting Signed Knowledge Capsules](04-signed-knowledge-capsules.md)** | Create immutable, cryptographically signed `.capsule` archives linking knowledge graphs to release tags. | `coppermind export-capsule` | Signed Knowledge Capsule |
| **[05. Episodic Scratchpad Integrity & Partition Quarantine](05-episodic-scratchpad-integrity.md)** | Validate working scratchpads, verify Ed25519 signatures, defang XML tool reflection, and quarantine untrusted observations. | `coppermind remember`<br/>`coppermind recall` | MemoryValidator & Quarantine Partition |
| **[06. Pure-Go Static Neural Recall & Temporal Filtering](06-static-neural-recall-and-reranking.md)** | Install offline `CMVEC1` embeddings, micro-batch reindex, and filter recall by time windows with `--explain`. | `coppermind models pull`<br/>`coppermind reindex-vectors` | `CMVEC1` + Composite ACT-R/MMR Reranker |
| **[07. Knowledge Graph Impact & Incremental AST Indexing](07-knowledge-graph-and-ast-indexing.md)** | Incrementally AST-chunk Go/Markdown repos and inspect 1-2 hop graph impact & contradiction warnings. | `coppermind index .`<br/>`coppermind graph impact` | SQLite `memory_edges` + `indexed_files` |
| **[08. `<8ms` Context Briefs, MCP Resources & Sleep Cycle](08-context-brief-inbox-and-sleep-cycle.md)** | Compile `<=800`-token workspace briefs, triage pending commit lens tickets, and run episodic consolidation. | `coppermind brief`<br/>`coppermind inbox`<br/>`coppermind consolidate` | Brief Compiler + Pending Inbox + Host Eval |
| **[09. Mergeable Cartridges & Local Memory Explorer](09-mergeable-cartridges-and-brain-explorer.md)** | Export, verify, and merge selective `.capsule` v2 cartridges and explore memories locally via `tui`/`ui`. | `coppermind capsule export`<br/>`coppermind capsule merge`<br/>`coppermind ui` | `.capsule` v2 + Loopback `127.0.0.1` Explorer |
| **[10. Obsidian Vault Watcher, Git-Tag Recall & Flightdeck Bridge](10-obsidian-vault-sync-timeline-and-flightdeck.md)** | Read-only hash-incremental Markdown/Obsidian `[[wikilink]]` sync, `--since v0.5.0` git-tag recall, Memory Explorer v2 timeline/lineage, and Flightdeck trace ingestion. | `coppermind watch`<br/>`coppermind capsule inspect`<br/>`coppermind ingest-flightdeck` | `os.OpenRoot` Watcher + Git Ref Resolver + Flightdeck Bridge |
| **[11. Hierarchical Platform Scopes & Inherited Knowledge](11-hierarchical-platform-scopes.md)** | Layer general platform guidance (`platform`) with component specifics (`platform/payments/webhooks`) inside one vault with ancestor inheritance, sibling exclusion, and `.coppermind.yaml` auto-scoping. | `coppermind remember --scope`<br/>`coppermind recall --scope`<br/>`coppermind scope list` | Indexed `scope` Column + `ScopeAffinity` Reranker + Merkle v2 |
