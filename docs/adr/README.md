# Coppermind Architectural Decision Records (ADRs)

This directory documents the key architectural decisions, cognitive storage models, and epistemic governance invariants governing [`bonjoski/coppermind`](https://github.com/bonjoski/coppermind).

## ADR Index

| ADR ID | Title | Status | Date | Scope |
| :--- | :--- | :--- | :--- | :--- |
| **[ADR-0001](0001-portable-cognitive-ai-brain-architecture.md)** | **Portable Cognitive AI Brain Architecture (Profile A & Profile B)** | `Accepted` | 2026-11-13 | `pkg/db`, `pkg/mcp`, `pkg/scratchpad` |
| **[ADR-0002](0002-feruchemical-lenses-cognitive-synthesis.md)** | **Feruchemical Lenses & Cognitive Memory Synthesis** | `Accepted` | 2026-11-15 | `pkg/lenses`, `pkg/worker` |
| **[ADR-0003](0003-epistemic-authority-memory-governance.md)** | **Epistemic Authority & Role-Based Memory Governance** | `Accepted` | 2026-11-15 | `pkg/security`, `pkg/db/postgres` |
| **[ADR-0004](0004-extensible-industry-radar-subsystem.md)** | **Extensible Industry Radar & Threat Intel Ingestion** | `Accepted` | 2026-11-16 | `pkg/radar`, `pkg/capsule` |
| **[ADR-0005](0005-lean-threat-model-lenses.md)** | **Lean Threat-Model Lenses & Differential Security Verification** | `Accepted` | 2026-11-17 | `pkg/lenses/threat` |

---

## Architectural Principles

1. **No Amnesia:** Agent experiences, decisions, architectural constraints, and diagnostic patterns survive cross-session reboots without cloud dependency.
2. **Dual-Profile Runtime:** Profile A (Embedded Pure-Go SQLite WAL + In-Memory RESP) for local laptops; Profile B (PostgreSQL 17 + pgvector + Redis + RabbitMQ) for distributed multi-agent clusters.
3. **Epistemic Authority:** Strict tiering of memory truth; raw Git source code and human ADRs (Tier 0/1) authoritatively override AI-derived inferences (Tier 2/3).
4. **Sub-5ms Query Retrieval:** Native MCP over stdio or UDS delivers hybrid vector/BM25 recall in `< 5ms` with zero process-wrapping overhead.
