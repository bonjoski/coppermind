# 💡 Coppermind End-User Use Cases & Recipes

> **Repository:** [`github.com/bonjoski/coppermind`](https://github.com/bonjoski/coppermind)  
> **Classification:** Developer Recipes & Task-Oriented Guides  
> **Source of Truth:** Authoritative Standard  

---

## Overview

**Coppermind** is a portable, sovereign cognitive AI brain and analytical synthesis engine for autonomous agents and developer workstations. Operating with pure-Go SQLite WAL mode, local cosine vector embeddings, BM25 full-text indexing, and multi-perspective analytical lenses, Coppermind ensures agents maintain long-term memory across sessions without external cloud SaaS dependencies.

This directory provides task-oriented recipes for common cognitive memory workflows.

---

## 📚 Recipe Catalog

| Recipe | Problem Addressed | Primary CLI Commands | Mechanism |
| :--- | :--- | :--- | :--- |
| **[01. Cross-Session Cognitive Memory & Retrieval](01-cross-session-memory.md)** | Store project architectural conventions, debugging findings, and ADRs; query via hybrid vector search. | `coppermind remember`<br/>`coppermind recall "<query>"` | Pure-Go SQLite WAL + Vector Index |
| **[02. Security Mentor Capsules for AI & Web Apps](02-security-mentor-capsules-for-ai-apps.md)** | Import signed/verified open-source security mental-model packs and receive `<= 120`-token passive nudges during ideation. | `coppermind capsule import`<br/>`coppermind recall --lens mentor "<topic>"` | Mentor Lens + Two-Gate Import Quarantine |
| **[02b. Automated Post-Commit Episodic Reflection](02-git-hook-reflection.md)** | Automatically parse, sanitize, and ingest git commit diffs into episodic memory via git hooks. | `coppermind hook install`<br/>`coppermind observations` | Git Post-Commit Hook |
| **[03. Product Owner Abuse-Case Acceptance Criteria](03-product-owner-abuse-case-criteria.md)** | Turn 5-question plain-English blast-radius triggers and user stories into `<= 3` sprint-ready `Given / When / Then` safety acceptance criteria (`<= 180` tokens, ephemeral). | `coppermind requirements --story "..."`<br/>`coppermind recall --lens requirements` | Requirements Lens + Curated PO Capsule |
| **[03b. Multi-Perspective Analytical Threat Lenses](03-analytical-threat-lenses.md)** | Run automated multi-persona reviews (`security-architect`, `devils-advocate`, `red-team-operator`) on RFC proposals. | `coppermind radar`<br/>`coppermind proposals` | Cognitive Lenses Engine |
| **[04. Exporting Signed Knowledge Capsules](04-signed-knowledge-capsules.md)** | Create immutable, cryptographically signed `.capsule` archives linking knowledge graphs to release tags. | `coppermind export-capsule` | Signed Knowledge Capsule |
| **[05. Episodic Scratchpad Integrity & Partition Quarantine](05-episodic-scratchpad-integrity.md)** | Validate working scratchpads, verify Ed25519 signatures, defang XML tool reflection, and quarantine untrusted observations. | `coppermind remember`<br/>`coppermind recall` | MemoryValidator & Quarantine Partition |
