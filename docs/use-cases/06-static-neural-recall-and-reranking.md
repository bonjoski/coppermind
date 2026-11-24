# Use Case 06: Pure-Go Static Neural Recall, Temporal Filtering & Score Explainability

> **Target:** Zero-API-key, zero-CGO semantic retrieval with sub-3ms recall and calibrated `[0.0, 1.0]` composite scoring.

## Scenario
Default hash-projection embeddings miss synonyms (`login` vs. `authentication`, `roadmap` vs. `architecture`). You want real local semantic similarity, recency/access reinforcement, repo affinity, MMR diversity, and time-windowed recall (`--since 7d`) without running Ollama or paying for embedding APIs.

## Recipe

```bash
# 1. Inspect active embedder and current vault vector coverage
coppermind models list

# 2. Install the offline 256-dim CMVEC1 static concept pack (or pull a pinned Model2Vec pack via --from-file / --url + --sha256)
coppermind models pull sovereign-dev-256

# 3. Re-embed existing vault nodes in lock-free WAL micro-batches
coppermind reindex-vectors --batch-size 128

# 4. Run temporal, repo-aware hybrid recall with full score explainability
coppermind recall --since 7d --hops 1 --explain "login credential expiry"
```

## Security & Concurrency Guarantees
- **Fail-Closed Pack Verification:** `CMVEC1` packs refuse symlinks (`os.Lstat`), bound dimensions (`<=1024`) and vocabulary (`<=250k`), and verify embedded + pinned SHA-256 checksums before loading.
- **Zero Write-on-Read Contention:** ACT-R access reinforcement coalesces asynchronously every 2 seconds through the single-writer WAL ring (`TAINT_*` nodes never receive access boosts).
- **Zero-Downtime Mixed-Dim Fallback:** Before `reindex-vectors` finishes, FTS5 BM25 rescues older mismatched-dimension nodes automatically.
