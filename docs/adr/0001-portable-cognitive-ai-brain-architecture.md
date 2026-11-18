# ADR-0001: Portable Cognitive AI Brain Architecture (Profile A & Profile B)

- **Status:** Accepted
- **Date:** 2026-11-13
- **Component:** `pkg/db`, `pkg/mcp`, `pkg/scratchpad`
- **Deciders:** Lead Cognitive Architect & Agent Memory Systems Engineer

---

## 1. Context & Problem Statement

Autonomous coding agents suffer from session amnesia: each invocation starts with a cold context window, unaware of past architectural decisions, failed attempts, and project conventions.
- Centralized proprietary AI memory SaaS leaks proprietary code and prompts to cloud providers.
- Local vector databases often require heavy Python runtimes or external Docker daemons, destroying lightweight developer ergonomics.

---

## 2. Decision Outcome

We built **Coppermind**, a portable, MCP-native cognitive AI memory runtime with pluggable storage profiles:

1. **Profile A (Local Micro-Appliance):**
   - Embedded pure-Go SQLite with Write-Ahead Logging (`WAL` mode) and a single-writer channel ring.
   - In-memory RESP-compatible scratchpad for ephemeral state and lock coordination across $N=8$ parallel subagents.
   - 128-dimensional FastText-style hashing vectorizer + SQLite FTS5 BM25 hybrid search.
2. **Profile B (Distributed Cluster):**
   - PostgreSQL 17 with `pgvector` HNSW indexes for enterprise multi-agent clusters.
   - Redis Cluster / Dragonfly for distributed scratchpads.
   - RabbitMQ AMQP 0-9-1 for asynchronous memory reflection workers.
3. **Native MCP Interface:**
   - Native Model Context Protocol (MCP) server over STDIO/UDS, dispatching memory queries (`recall`, `remember`) in `< 1.8ms`.

---

## 3. Consequences

- **Positive:** Zero SaaS dependency; sub-5ms memory retrieval; works completely offline on developer laptops.
- **Negative:** SQLite single-writer concurrency requires a channel-based write serializer in Profile A.
