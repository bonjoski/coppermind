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
| **[02. Automated Post-Commit Episodic Reflection](02-git-hook-reflection.md)** | Automatically parse, sanitize, and ingest git commit diffs into episodic memory via git hooks. | `coppermind hook install`<br/>`coppermind observations` | Git Post-Commit Hook |
| **[03. Multi-Perspective Analytical Threat Lenses](03-analytical-threat-lenses.md)** | Run automated multi-persona reviews (`security-architect`, `devils-advocate`, `red-team-operator`) on RFC proposals. | `coppermind radar`<br/>`coppermind proposals` | Cognitive Lenses Engine |
| **[04. Exporting Signed Knowledge Capsules](04-signed-knowledge-capsules.md)** | Create immutable, cryptographically signed `.capsule` archives linking knowledge graphs to release tags. | `coppermind export-capsule` | Signed Knowledge Capsule |
