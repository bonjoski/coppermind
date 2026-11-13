# 🧠 Coppermind (`bonjoski/coppermind`)

> **Portable Cognitive AI Brain & Sovereign Agent Memory Runtime**  
> *Zero-SaaS, MCP-native long-term episodic/semantic memory, hybrid vector retrieval, and fast working scratchpad for autonomous AI agents.*

---

## Overview

In Brandon Sanderson's *Mistborn*, Feruchemists store memories, mental speed, and knowledge inside copper metalminds—retrieving them with perfect fidelity.

**Coppermind** is a self-sovereign, portable cognitive AI brain engineered as an **MCP-native daemon**. It solves the "amnesiac agent" crisis by giving autonomous AI coding agents (Claude Code, Cursor, Antigravity, OpenCode, Aider) a persistent, zero-dependency cognitive memory runtime that runs locally on developer workstations or scales into distributed team clusters.

```mermaid
flowchart TD
    subgraph ClientPlane ["Client & Agent Plane"]
        Agents["AI Agents & IDEs<br/>(Claude Code, Cursor, Antigravity)"]
    end

    subgraph CoppermindRuntime ["Coppermind MCP Core (Go 1.27+)"]
        MCP["MCP JSON-RPC 2.0 Engine<br/>(STDIO / SSE / UDS)"]

        subgraph CognitiveTiers ["Cognitive Memory Hierarchy"]
            Working["Working Memory Tier<br/>(Fast In-Memory Scratchpad & Mutexes)"]
            Episodic["Episodic Memory Tier<br/>(Chronological Logs & Commit History)"]
            Semantic["Semantic Memory Tier<br/>(128-dim Cosine Vector Search)"]
        end

        subgraph StorageCore ["Storage Engine"]
            SQLite["Pure-Go SQLite (WAL Mode)<br/>(Single-Writer Ring + Parallel Reader Pool)"]
        end
    end

    Agents <-->|MCP Tools (coppermind_*)| MCP
    MCP --> CognitiveTiers
    CognitiveTiers --> StorageCore
```

---

## Core Capabilities

1. **MCP-Native First**: Exposes standard Model Context Protocol tools (`coppermind_remember`, `coppermind_recall`, `coppermind_scratchpad`, `coppermind_status`) directly over STDIO, allowing instant mounting in any IDE agent configuration.
2. **Zero Hop Tax & Sub-10ms Latency**: Connects over persistent STDIO or Unix Domain Sockets; eliminates intermediate CLI wrapper latency.
3. **Multi-Agent Concurrency ($N=8$ Stress-Tested)**: Features a single-writer channel worker with SQLite Write-Ahead Logging (WAL mode), enabling 8+ parallel subagents to store, search, and lock memory without database collisions or lock timeouts.
4. **Cognitive Security & Taint Defense**: Normalizes all inbound memories via NFKC Unicode decomposition and strips invisible zero-width characters (OWASP LLM01 indirect prompt injection defense).
5. **Absolute Secret & Credential Quarantine**: Strict fail-closed defense scanning for private keys, AWS/OpenAI/Anthropic/GitHub API keys, and high-entropy tokens. Raw keys are rejected with typed security errors, and embedded tokens are redacted (`[REDACTED_*]`) before reaching SQLite or vector embeddings.

---

## Quickstart

### Installation & Build

```bash
# Build the binary
go build -o bin/coppermind ./cmd/coppermind

# Verify installation
./bin/coppermind version
```

### CLI Usage

```bash
# Store an architectural invariant into memory
coppermind remember --category architecture "Always use Go 1.27 pure-Go SQLite with WAL mode"

# Semantic recall using natural language query
coppermind recall "What database engine and journal mode do we use?"

# Fast in-memory scratchpad operations
coppermind scratchpad set active_task "Refactor auth middleware"
coppermind scratchpad get active_task
coppermind scratchpad keys

# Brain health and metrics
coppermind status
```

### Connecting to AI Coding Agents (Claude Code, Cursor, Antigravity)

Add Coppermind to your agent's MCP configuration (`mcp_config.json` or `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "coppermind": {
      "command": "coppermind",
      "args": ["mcp"]
    }
  }
}
```

---

## Architectural Plans & Governance

Coppermind is governed by the `bonjoski` sovereign AI agent security ecosystem. Architectural plans and STRIDE threat models are maintained at:
* [`spanreed/docs/plans/accepted/2026-11-13-coppermind-portable-ai-brain-rfc.md`](https://github.com/bonjoski/spanreed)

---

## License

MIT License. Copyright (c) 2026 Ben Skolmoski (`bonjoski`).
