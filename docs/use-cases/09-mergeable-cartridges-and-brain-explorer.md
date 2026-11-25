# Use Case 09: Mergeable Ed25519 Knowledge Cartridges & Local Memory Explorer (`tui` / `ui`)

> **Target:** Shareable, non-destructive `.capsule` v2 memory cartridges and visual local-only memory inspection (`127.0.0.1`).

## Scenario
You want to export just your `fabrial` architectural invariants into a signed cartridge, merge it into another workstation vault without overwriting existing memories, and visually explore your knowledge graph, score breakdowns, and pending inbox locally.

## Recipe

```bash
# 1. Export a selective, Ed25519-signed mergeable cartridge (.capsule v2)
coppermind capsule keygen --out ./keys
coppermind capsule pack-memories --repo fabrial --tier TIER_1_ARCHITECTURE --key ./keys/ed25519.key --out fabrial-arch.capsule

# 2. Non-destructively merge into another vault (verifies Merkle root, Ed25519 signature, & Stormcage quarantine)
coppermind capsule merge --pubkey ./keys/ed25519.pub fabrial-arch.capsule

# 3. Explore your memory vault interactively in the terminal (4 tabs: Search, Graph, Inbox/Obs, Health)
coppermind tui

# 4. Or launch the strictly local 127.0.0.1 visual Force-Graph Explorer (read-only by default)
coppermind ui
# Enable authenticated POST resolve/approve actions:
coppermind ui --allow-curate
```

## Security Guarantees
- **Anti-Zip-Bomb & Tar-Slip Defense:** `capsule merge` enforces a `50 MiB` decompressed cap, `tar.TypeReg`-only entries, Merkle root checks, and Stormcage secret/prompt-injection quarantine on every record.
- **Anti-DNS-Rebinding Localhost UI:** `coppermind ui` refuses non-loopback addresses fail-closed, binds to `127.0.0.1:0`, validates `Host: ^127\.0\.0\.1:\d+$`, requires a 256-bit CSPRNG token exchanged for an `HttpOnly; SameSite=Strict` cookie, sets strict CSP (`default-src 'self'`), and requires `X-Coppermind-CSRF` for `--allow-curate` mutations.
