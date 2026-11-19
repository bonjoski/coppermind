# 🧠 Coppermind (`bonjoski/coppermind`)

[![CI](https://github.com/bonjoski/coppermind/actions/workflows/ci.yml/badge.svg)](https://github.com/bonjoski/coppermind/actions/workflows/ci.yml)
[![SLSA 2](https://slsa.dev/images/gh-badge-level2.svg)](https://slsa.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

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

    Agents <-->|"MCP Tools (coppermind_*)"| MCP
    MCP --> CognitiveTiers
    CognitiveTiers --> StorageCore
```

---

## Core Capabilities

1. **MCP-Native First**: Exposes standard Model Context Protocol tools (`coppermind_remember`, `coppermind_recall`, `coppermind_scratchpad`, `coppermind_dispatch_task`, `coppermind_status`) directly over STDIO, allowing instant mounting in any IDE agent configuration.
2. **Zero Hop Tax & Sub-10ms Latency**: Connects over persistent STDIO or Unix Domain Sockets; eliminates intermediate CLI wrapper latency.
3. **Multi-Agent Concurrency ($N=8$ Stress-Tested)**: Features a single-writer channel worker with SQLite Write-Ahead Logging (WAL mode), enabling 8+ parallel subagents to store, search, and lock memory without database collisions or lock timeouts.
4. **Cognitive Security & Taint Defense**: Normalizes all inbound memories via NFKC Unicode decomposition and strips invisible zero-width characters (OWASP LLM01 indirect prompt injection defense).
5. **Absolute Secret & Credential Quarantine**: Strict fail-closed defense scanning for private keys, AWS/OpenAI/Anthropic/GitHub API keys, and high-entropy tokens. Raw keys are rejected with typed security errors, and embedded tokens are redacted (`[REDACTED_*]`) before reaching SQLite or vector embeddings.
6. **Asynchronous AMQP / RabbitMQ Task Engine**: Dispatches background cognitive workflows (`deep_reflect`, `summarize_session`, `defrag_memory`) onto an embedded topic bus or external RabbitMQ cluster (`COPPERMIND_RABBITMQ_URL`).
7. **LiteLLM Model Router**: Autonomous reflection and synthesis engine with outbound API key scrubbing on upstream HTTP error frames.
8. **Cognitive Lenses**: Asynchronous, event-driven analytical personas (`red-team`, `security-architect`, `systems-architect`, `drift-auditor`, `synthesizer`, `devils-advocate`) that subscribe to bus events, evaluate memories across cognitive tiers, and synthesize structured observations back into project vaults without recursive loops.

---

## 🔍 Cognitive Lenses Subsystem

Cognitive Lenses provide continuous analytical evaluation of project memories via configurable personas:

* **`red-team`**: Aggressively attacks code, configurations, and sandbox policies from an adversary's mindset; identifies concrete exploit vectors, sandbox escapes (Seatbelt/Landlock/seccomp), TOCTOU symlink races, parameter injections, and token replay.
* **`security-architect`**: Audits code diffs, command executions, and configuration changes for OWASP vulnerabilities, credential exposure, unsafe syscalls, and privilege escalation vectors.
* **`systems-architect`**: Analyzes architectural coherence, modularity, single-responsibility invariants, and multi-agent concurrency bottlenecks.
* **`drift-auditor`**: Detects drift between architectural specifications/docs and live implementations, flagging regressions and configuration drift.
* **`synthesizer`**: Cross-correlates memories across sessions, distilling high-level decisions, patterns, and overarching system state.
* **`devils-advocate`**: Stress-tests technical decisions, ADRs, and plans; highlights single-points-of-failure, scalability walls, and unexamined tradeoffs.

### Key Architectural Invariants
* **Zero-Cost Pre-Filter Gates**: Fast regex/AST matching (e.g. scanning for `exec`, `syscall`, `unsafe`, credentials) skips 85%+ of candidate memories before invoking LLMs, preserving local VRAM and CPU.
* **OWASP LLM01 Prompt Injection Defense**: Candidate memories and code diffs are fenced inside `<untrusted_artifact id="...">...</untrusted_artifact>` tags with strict system directives instructing the model to treat contents strictly as data, never directives.
* **Loop Prevention (`derived=true`)**: Lenses write observations with `derived=true`. The brain manager and topic bus guarantee that derived records never emit `ingest.*` or `episodic.*` events, making recursive trigger cascades structurally impossible.
* **Deterministic Deduplication**: Computes `SHA256(project + ":" + lens_name + ":" + target_hash + ":" + summary)` to skip duplicate observations and eliminate alert fatigue.
* **Append-Only Authority**: Lenses create observations and resolve existing observations from the same lens; they can never alter or delete canonical memories.

### Configuration (`~/.coppermind/lenses.yaml`)
Lenses are declaratively configured with sensible embedded defaults when the file is absent:

```yaml
version: "1"
lenses:
  - name: "security-architect"
    model: "local-coder"
    subscribe:
      - "episodic.commit"
      - "ingest.code"
      - "dispatch.deep_reflect"
    recall_categories:
      - "architecture"
      - "security"
      - "invariant"
    prefilter_regex: "(?i)(exec|unsafe|syscall|os\\.Open|crypto|socket|eval|password|secret|token|api_key|auth|chmod|chown)"
    system_prompt: |
      You are the Lead Security Architect. Analyze the provided untrusted artifact for vulnerabilities.
      Respond strictly in JSON: {"findings": [{"severity": "high", "category": "security", "summary": "...", "evidence": "..."}]}
```

### CLI & MCP Usage

```bash
# Trigger deep reflection using a specific lens or all lenses
coppermind dispatch reflect --lens security-architect --since 24h
coppermind dispatch reflect --lens devils-advocate --since 24h

# Recall memories and filter strictly to observations from a specific lens
coppermind recall --lens security-architect "command execution"

# Recall canonical memories with linked cognitive lens observations automatically attached (default)
coppermind recall --include-observations "sandbox configuration"

# Inspect and resolve open cognitive lens observations
coppermind observations --status open --min-severity high
coppermind observations --resolve <observation-id>

# Automated Git Post-Commit Hook with background lens evaluation
coppermind hook install
coppermind hook check
```

In MCP:
* `coppermind_recall` accepts optional `lens` (string filter) and `include_observations` (bool, default `true`).
* `coppermind_dispatch_task` accepts `task="reflect"` with optional `lens` argument.
* On `coppermind mcp` startup, the active project's scratchpad is automatically seeded with the top 3 unresolved `high`/`critical` observations.

---

## Quickstart

### Installation & Build

```bash
# Via Homebrew Tap (Recommended)
brew tap bonjoski/tap
brew install coppermind

# Or build from source with Go 1.27+
go build -o bin/coppermind ./cmd/coppermind
cp bin/coppermind ~/.local/bin/coppermind
```

### CLI Usage

```bash
# Manage isolated project vaults (0% cross-contamination)
coppermind project list
coppermind project use personal
coppermind --project personal remember --category "family" "Bailey the dog is allergic to chicken"
coppermind --project personal recall "What is Bailey allergic to?"

# Store an architectural invariant into default (github) vault
coppermind remember --category architecture "Always use Go 1.27 pure-Go SQLite with WAL mode"

# Semantic and BM25 hybrid recall using natural language query
coppermind recall "What database engine and journal mode do we use?"

# Fast in-memory scratchpad operations
coppermind scratchpad set active_task "Refactor auth middleware"
coppermind scratchpad get active_task
coppermind scratchpad keys

# Install automated episodic git commit hook in current repository
coppermind hook install
coppermind hook status

# Run background reflection or memory defragmentation
coppermind dispatch summarize_session
coppermind dispatch extract_decisions
coppermind dispatch defrag_memory

# Purge expired TTL nodes and compact database
coppermind vacuum

# Run 10-pillar diagnostic inspection
coppermind doctor

# Brain health and metrics
coppermind status
```

---

## 💡 Core Use Cases & Recipes

Every primary developer use case is backed by dedicated, copy-pasteable recipes in [**`docs/use-cases/`**](docs/use-cases/README.md):

| Use Case | Scenario & Quick Recipe | Full Guide |
| :--- | :--- | :--- |
| **Cross-Session Cognitive Memory & Retrieval** | Store and query architectural facts via hybrid vector search:<br/>`coppermind remember` && `coppermind recall "<query>"` | [Guide](docs/use-cases/01-cross-session-memory.md) |
| **Automated Git Post-Commit Reflection** | Ingest commit diffs and flag architectural drifts automatically:<br/>`coppermind hook install` && `coppermind observations` | [Guide](docs/use-cases/02-git-hook-reflection.md) |
| **Multi-Perspective Analytical Threat Lenses** | Stress-test RFCs with automated Devil's Advocate and Red Team lenses:<br/>`coppermind radar --lenses all --file <doc>` | [Guide](docs/use-cases/03-analytical-threat-lenses.md) |
| **Exporting Signed Knowledge Capsules** | Create immutable, signed `.capsule` archives linking memory to release tags:<br/>`coppermind export-capsule --sign` | [Guide](docs/use-cases/04-signed-knowledge-capsules.md) |
| **Episodic Scratchpad Integrity & Observation Quarantine** | Verify Ed25519 signatures, defang XML tool reflections, and quarantine untrusted observations:<br/>`coppermind remember` && `coppermind recall` | [Guide](docs/use-cases/05-episodic-scratchpad-integrity.md) |

---

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

## Runtime Profiles: Profile A (Local) vs Profile B (Cluster)

Coppermind features a **dual-profile runtime architecture** designed to meet the developer where they work: zero-dependency micro-appliance on local machines, or resilient high-throughput cluster on Kubernetes.

| Architectural Component | Profile A: Local Micro-Appliance (Default) | Profile B: Distributed Cluster Appliance |
| :--- | :--- | :--- |
| **Target Workload** | Individual developer laptops, CI runners, edge workstations | Multi-agent teams, Kubernetes clusters, enterprise pools |
| **Activation Environment** | `COPPERMIND_PROFILE=local` (or unset) | `COPPERMIND_PROFILE=cluster` |
| **Relational Storage** | Pure-Go SQLite in WAL mode (`coppermind.db`) | PostgreSQL 17 (`pgvector/pgvector:pg17`) |
| **Vector Engine** | Embedded 128-dim subword vectorizer + FTS5 BM25 | `pgvector` HNSW cosine index (`vector(128)`) |
| **Working Memory** | In-memory thread-safe RESP scratchpad with mutexes | Redis Cluster 7.x / Dragonfly (`COPPERMIND_REDIS_ADDR`) |
| **Task Queue** | Embedded Go buffered channel topic bus (256 queue) | RabbitMQ Cluster AMQP 0-9-1 (`COPPERMIND_RABBITMQ_URL`) |
| **Model Router & Keys** | LiteLLM client + Locksmith Touch ID biometric leasing | Centralized LiteLLM proxy pool + SPIFFE mTLS tokens |
| **Resource Footprint** | Single Go binary (<50MB, <80MB RAM, <150ms cold boot) | OCI container pods (`deploy/helm/coppermind`) |

---

### Configuration Environment Variables

| Variable | Default Value | Profile | Description |
| :--- | :--- | :--- | :--- |
| `COPPERMIND_PROFILE` | `local` | Both | Runtime profile selection: `local` or `cluster`. |
| `COPPERMIND_DATA_DIR` | `~/.coppermind` | Both | Root directory for SQLite databases, vaults, and sockets. |
| `COPPERMIND_PROJECT` | `github` | Both | Active project vault (enforces 0% context cross-contamination). |
| `COPPERMIND_POSTGRES_URL`| `postgres://coppermind:sovereign_secret@localhost:5433/coppermind?sslmode=disable` | Profile B | Connection string for PostgreSQL 17 + pgvector. |
| `COPPERMIND_PG_PORT` | `5433` | Profile B | Port mapped for PostgreSQL container in Docker Compose. |
| `COPPERMIND_REDIS_ADDR` | `127.0.0.1:6379` | Profile B | Host and port for external Redis working memory scratchpad. |
| `COPPERMIND_RABBITMQ_URL`| `amqp://guest:guest@localhost:5672/` | Profile B | AMQP broker connection URL for async task queues. |
| `COPPERMIND_LITELLM_URL` | *None (offline fallback)* | Both | Optional upstream LiteLLM gateway endpoint for deep reflection. |
| `OPENAI_API_KEY` | *None* | Both | Optional API key (auto-resolved from Locksmith Secure Enclave if installed). |

---

### Docker Compose Cluster Setup (Profile B)

A production-grade Docker Compose manifest is included at the repository root (`docker-compose.yml`), provisioning PostgreSQL 17 with `pgvector`, Redis 7, RabbitMQ 3, and Coppermind:

```bash
# 1. Start the distributed Profile B infrastructure in the background
docker compose up -d

# 2. Verify all cluster services are healthy
docker compose ps

# 3. Confirm pgvector extension is operational
docker compose exec postgres psql -U coppermind -d coppermind -c \
  "SELECT extname, extversion FROM pg_extension WHERE extname = 'vector';"

# 4. Confirm Redis working memory responds
docker compose exec redis redis-cli ping

# 5. Run Coppermind diagnostic inspection against the cluster
COPPERMIND_PROFILE=cluster coppermind doctor

# 6. Store and recall memories using Profile B cluster
COPPERMIND_PROFILE=cluster coppermind remember --category architecture "Postgres 17 pgvector cluster verified"
COPPERMIND_PROFILE=cluster coppermind recall "Which database engine is active?"

# 7. Tear down cluster stack
docker compose down
```

---

### Kubernetes Helm Deployment (Profile B)

For enterprise team clusters and cloud-native orchestration, deploy Coppermind via its official Helm chart located at `deploy/helm/coppermind`:

```bash
# 1. Inspect default chart values
helm show values deploy/helm/coppermind

# 2. Deploy Coppermind into dedicated namespace
helm upgrade --install coppermind deploy/helm/coppermind \
  --namespace coppermind \
  --create-namespace \
  --set profile=cluster \
  --set postgres.url="postgres://coppermind:secret@postgres-service.coppermind.svc.cluster.local:5432/coppermind?sslmode=disable" \
  --set redis.addr="redis-service.coppermind.svc.cluster.local:6379" \
  --set rabbitmq.url="amqp://guest:guest@rabbitmq-service.coppermind.svc.cluster.local:5672/"

# 3. Verify running pods and service endpoints
kubectl get pods -n coppermind -l app.kubernetes.io/name=coppermind
kubectl get svc -n coppermind coppermind
```

---

### MCP Agent Configurations (Claude Code, Cursor, Antigravity)

Configure your AI agent to mount Coppermind using either Profile A (local zero-dependency) or Profile B (connected to your team cluster):

#### Profile A: Local Sovereign STDIO Mount (`claude_desktop_config.json` or `mcp_config.json`)
```json
{
  "mcpServers": {
    "coppermind": {
      "command": "coppermind",
      "args": ["mcp"],
      "env": {
        "COPPERMIND_PROFILE": "local",
        "COPPERMIND_PROJECT": "github"
      }
    }
  }
}
```

#### Profile B: Distributed Cluster STDIO Mount (`mcp_config.json`)
```json
{
  "mcpServers": {
    "coppermind-cluster": {
      "command": "coppermind",
      "args": ["mcp"],
      "env": {
        "COPPERMIND_PROFILE": "cluster",
        "COPPERMIND_POSTGRES_URL": "postgres://coppermind:sovereign_secret@localhost:5433/coppermind?sslmode=disable",
        "COPPERMIND_REDIS_ADDR": "127.0.0.1:6379",
        "COPPERMIND_RABBITMQ_URL": "amqp://guest:guest@localhost:5672/",
        "COPPERMIND_PROJECT": "team-shared"
      }
    }
  }
}
```

---

## Ecosystem Integration

Coppermind operates as the persistent memory and cognitive runtime tier within the `bonjoski` sovereign AI agent security ecosystem, integrating natively alongside:
* [**`bonjoski/fabrial`**](https://github.com/bonjoski/fabrial): Unified security fabric and dynamic multi-tier agent router.
* [**`bonjoski/airlock`**](https://github.com/bonjoski/airlock): Sub-15ms kernel-enforced sandbox for AI agents and build tools.
* [**`bonjoski/locksmith`**](https://github.com/bonjoski/locksmith): Hardware biometric secrets vault and MCP credential manager.
* [**`bonjoski/homebrew-tap`**](https://github.com/bonjoski/homebrew-tap): Official distribution tap for pre-compiled binaries.

---

## SLSA Provenance & Verification

Coppermind adheres to the **SLSA v1.0** specification.

Verify provenance with GitHub CLI:
```bash
gh attestation verify coppermind --repo bonjoski/coppermind
```

Or verify offline using Soulcaster:
```bash
soulcaster verify --attestation coppermind.intoto.jsonl bin/coppermind
```

---

## License

MIT License. Copyright (c) 2026 Ben Skolmoski (`bonjoski`).
