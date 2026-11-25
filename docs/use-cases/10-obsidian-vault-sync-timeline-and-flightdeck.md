# Use Case 10: Local Obsidian/ADR Vault Sync, Git-Tag Temporal Recall, Memory Explorer v2 & Flightdeck Post-Mortems

> **Status:** Available in `coppermind v0.8.0+` (`RFC-2026-11-24-57`)  
> **Scope:** 100% local, single-developer workstation DevEx — zero cloud sync, zero external API keys, read-only filesystem ingestion.

---

## 1. Sync a Local Obsidian / Markdown / ADR Folder (Read-Only)

Index any personal Obsidian vault or repository `docs/adrs/` folder into Coppermind with SHA-256 incremental hashing, YAML frontmatter parsing (`title`, `tags`, `aliases`, `status`), Obsidian `[[wikilink]]` graph edge extraction (`note:<slug>`), and automatic deleted-note pruning:

```bash
# One-shot read-only sync into your isolated "personal" vault
coppermind --project personal watch --once ~/Obsidian/PersonalVault

# Continuous read-only background watcher (5s hash-incremental poll)
coppermind --project personal watch --interval 5s ~/Obsidian/PersonalVault

# Sync architecture decision records with explicit category
coppermind watch --once --category adr ./docs/adrs
```

### Security Invariants
- **Read-Only Guarantee:** `coppermind watch` NEVER modifies, renames, or writes to any file inside your Markdown/Obsidian directory.
- **Symlink Escape Refusal:** Uses Go's syscall-confined `os.OpenRoot` plus `os.Lstat` to refuse symlinked vault roots and symlinked files pointing outside your vault fail-closed.
- **Wikilink Edge Flood Cap:** Strictly caps extracted `[[wikilink]]` graph edges at `32` per note (`graph.MaxEdgesPerNode`).
- **Stormcage Quarantine:** Notes containing raw private keys or critical prompt-injection payloads are quarantined before hitting SQLite.
- **Session Isolation:** Notes live in `session_id="vault:<dir>"`, so modifying or deleting notes never corrupts your episodic Merkle hash chains.

---

## 2. Git-Tag & Natural-Language Temporal Recall

Query what changed since a release tag or natural timeframe across both CLI and MCP:

```bash
# Recall everything learned or decided since a local git tag
coppermind recall --since v0.7.0 "embedding slab latency"
coppermind recall --since tag:v0.5.0 --explain "SQLite WAL concurrency"

# Natural-language time aliases
coppermind recall --since yesterday "hook ingest"
coppermind recall --since last-week --before today "security audit"
```

All git refs are validated against a strict allowlist (`^[A-Za-z0-9][A-Za-z0-9._/-]{0,63}$`, blocking flag injection and `..` traversal) and resolved via bounded `250ms` `git log -1 --format=%cI <ref> --`.

---

## 3. Selective `.capsule` v2 Export & Offline Inspection

Export a filtered, Ed25519-signed subset of memories and preview any third-party cartridge offline before merging it into your vault:

```bash
# Selective cartridge export (alias for pack-memories when filter/key flags are passed)
coppermind capsule export \
  --repo fabrial \
  --tier TIER_1_ARCHITECTURE \
  --since v0.5.0 \
  --key ./keys/ed25519.key \
  --out fabrial-arch.capsule

# Read-only offline inspection (verifies Merkle root, Ed25519 signature, and previews 5 records)
coppermind capsule inspect --pubkey ./keys/ed25519.pub fabrial-arch.capsule

# Non-destructive merge into an existing vault (deduped by SHA-256)
coppermind capsule merge --pubkey ./keys/ed25519.pub fabrial-arch.capsule
```

---

## 4. Memory Explorer v2 (`coppermind ui` & `coppermind tui`)

Inspect memory clusters, walk supersession chains, browse your chronological episodic timeline, approve/reject `PROPOSED` learnings, and prune noisy chunks:

```bash
# Read-only local browser UI (strictly 127.0.0.1 ephemeral port + 256-bit bearer token)
coppermind ui

# Enable CSRF-gated curation (Resolve, Approve/Reject proposals, Delete non-sovereign chunks)
coppermind ui --allow-curate

# Interactive zero-dependency terminal explorer
coppermind tui
# Inside TUI:
#   timeline 20          -> chronological episodic feed
#   lineage <memory_id>  -> supersession ancestors & audit rationale
#   proposals            -> list PROPOSED learnings
#   approve <id>         -> promote to TIER_1_ARCHITECTURE
#   reject <id>          -> mark REJECTED
#   delete <id>          -> delete noisy chunk (refuses TIER_0_SOVEREIGN fail-closed!)
```

> **Fail-Closed Safety:** Both `DELETE /api/v1/memories/{id}` and TUI `delete <id>` unconditionally refuse deleting `TIER_0_SOVEREIGN` memories (`403 Forbidden`), requiring explicit supersession instead.

---

## 5. Flightdeck Post-Mortem Trace Ingestion

Convert failed shell/agent command traces paired with their recovery commands into linked `dead_end` + `troubleshooting` memories connected by a `caused_by` knowledge graph edge:

```bash
coppermind ingest-flightdeck --repo coppermind ./flightdeck-trace.jsonl
```

Traces are capped at `16 MiB`, refuse symlinks fail-closed, and pass every stderr/command payload through secret redaction and Stormcage prompt-injection quarantine before storage.

---

## 6. Full Profile A (SQLite) & Profile B (PostgreSQL + Redis) Parity

All `v0.7`–`v0.8` capabilities run identically across **Profile A (`COPPERMIND_PROFILE=local` — pure-Go SQLite WAL + in-memory scratchpad)** and **Profile B (`COPPERMIND_PROFILE=cluster` — self-hosted PostgreSQL 17 `pgvector` + Redis/Dragonfly)** via backend-agnostic `pkg/storage` capability interfaces (`GraphStore`, `IndexedFileStore`, `InboxStore`, `VectorAdminStore`, `ExplorerStore`, `CartridgeStore`) and atomic Redis Lua `CompareAndSwap` (`EVAL`).

