# Claude Code Guidelines for `coppermind`

## Build & Test Commands
- **Build Binary:** `go build -o bin/coppermind ./cmd/coppermind`
- **Unit & Concurrency Tests:** `go test -v ./...`
- **Run Daemon/MCP:** `./bin/coppermind mcp`
- **Remember Command:** `./bin/coppermind remember --category architecture "your memory"`
- **Recall Command:** `./bin/coppermind recall "your query"`
- **Dispatch Command:** `./bin/coppermind dispatch deep_reflect`
- **Status Command:** `./bin/coppermind status`

## Code Style & Architectural Invariants
- Use pure-Go SQLite (`modernc.org/sqlite`) with WAL mode (`PRAGMA journal_mode=WAL`).
- All persistent writes must route through the single-writer channel worker to guarantee zero lock contention across parallel subagents.
- Text normalization via `golang.org/x/text/unicode/norm` (NFKC) and zero-width rune stripping before vector embedding.
- Strict credential quarantine via `pkg/security`: raw private keys fail closed, and embedded API keys are redacted with typed placeholders before persistence.
- FastText-style subword/word n-gram hashing embedder producing L2-normalized 128-dimensional vectors.
- Strict adherence to Model Context Protocol (MCP) JSON-RPC 2.0 specifications.

## Commit Invariants
- Mandatory cryptographic signing with GPG key `7BB5B44244E586B0` (`git commit -S`).
- Present diff and test output for explicit user sign-off before committing.
