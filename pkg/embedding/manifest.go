package embedding

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ModelSpec defines a known static embedding pack supported by `coppermind models pull`.
type ModelSpec struct {
	Alias       string `json:"alias"`
	Description string `json:"description"`
	Dimension   int    `json:"dimension"`
	URL         string `json:"url,omitempty"`
	SHA256      string `json:"sha256,omitempty"`
	BuiltIn     bool   `json:"built_in"`
}

// KnownModels lists supported local static neural embedding packs.
var KnownModels = []ModelSpec{
	{
		Alias:       "sovereign-dev-256",
		Description: "Zero-network built-in 256-dim technical semantic concept pack (generated deterministically offline).",
		Dimension:   256,
		BuiltIn:     true,
	},
	{
		Alias:       "potion-base-8m",
		Description: "Model2Vec Potion-base-8M int8 CMVEC1 pack (supply --from-file <path> or --url + --sha256 for air-gapped/pinned install).",
		Dimension:   256,
		BuiltIn:     false,
	},
}

// DefaultModelsDir returns ~/.coppermind/models (or COPPERMIND_DATA_DIR/models).
func DefaultModelsDir() string {
	if dataDir := strings.TrimSpace(os.Getenv("COPPERMIND_DATA_DIR")); dataDir != "" {
		return filepath.Join(dataDir, "models")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", ".coppermind", "models")
	}
	return filepath.Join(home, ".coppermind", "models")
}

// DefaultStaticModelPath returns the canonical auto-discovered default CMVEC1 path.
func DefaultStaticModelPath() string {
	if explicit := strings.TrimSpace(os.Getenv("COPPERMIND_STATIC_MODEL")); explicit != "" {
		return explicit
	}
	return filepath.Join(DefaultModelsDir(), "default.cmvec")
}

// semanticConceptGroups encodes curated software/security engineering concept clusters
// used both by BuildSovereignDevPack (256-dim offline CMVEC1 pack) and by LocalHashEmbedder's
// synonym expansion. Terms in the same group share a strong semantic concept axis.
var semanticConceptGroups = [][]string{
	{"auth", "authentication", "login", "signin", "oauth", "oidc", "jwt", "dpop", "spiffe", "svid", "identity", "iam", "credential", "session", "token", "rbac", "authz"},
	{"secret", "secrets", "apikey", "api_key", "password", "passwd", "keychain", "vault", "enclave", "touchid", "tpm", "biometric", "locksmith", "redaction", "shield", "quarantine"},
	{"database", "db", "sqlite", "postgres", "postgresql", "pgvector", "sql", "wal", "schema", "migration", "storage", "query", "index", "fts5", "bm25", "vacuum"},
	{"memory", "memories", "recall", "remember", "retrieval", "search", "vector", "embedding", "embeddings", "semantic", "cosine", "rerank", "mmr", "episodic", "scratchpad", "coppermind"},
	{"roadmap", "plan", "plans", "rfc", "adr", "architecture", "architectural", "design", "blueprint", "specification", "spec", "decision", "invariant", "invariants", "milestone"},
	{"security", "vuln", "vulnerability", "cve", "ghsa", "advisory", "exploit", "attack", "stride", "threat", "redteam", "red-team", "audit", "hardening", "sentinel", "firewall"},
	{"injection", "prompt", "llm01", "owasp", "taint", "sanitizer", "sanitization", "nfkc", "homoglyph", "stormcage", "delimiter", "untrusted", "poisoning", "jailbreak"},
	{"sandbox", "isolation", "confinement", "seatbelt", "landlock", "seccomp", "microvm", "hypervisor", "libkrun", "airlock", "aegisbox", "airgap", "escape", "symlink", "traversal", "zipslip"},
	{"supply", "supply-chain", "dependency", "dependencies", "package", "slopsquatting", "typosquat", "quarry", "semver", "argus", "sbom", "cyclonedx", "bomhound", "slsa", "provenance", "soulcaster", "attestation"},
	{"bug", "bugs", "defect", "regression", "crash", "failure", "deadlock", "race", "timeout", "fix", "patch", "remediation", "dead_end", "postmortem", "troubleshooting"},
	{"concurrency", "concurrent", "parallel", "subagent", "subagents", "worktree", "worktrees", "mutex", "lock", "contention", "channel", "goroutine", "atomic", "throughput", "latency", "hop"},
	{"mcp", "jsonrpc", "stdio", "tool", "tools", "prompt", "prompts", "resource", "resources", "lens", "lenses", "mentor", "capsule", "capsules", "handoff", "brief"},
	{"git", "commit", "commits", "branch", "diff", "hook", "hooks", "merge", "repo", "repository", "ast", "chunk", "chunking", "indexer", "indexing", "symbol"},
	{"crypto", "cryptographic", "ed25519", "sha256", "hmac", "merkle", "signature", "signing", "verify", "verification", "gpg", "cosign", "dsse", "receipt", "receipts"},
	{"graph", "edge", "edges", "node", "nodes", "neighbor", "neighbors", "hop", "hops", "impact", "contradiction", "supersede", "supersession", "lineage", "ancestor"},
	{"ui", "tui", "explorer", "visualizer", "dashboard", "localhost", "loopback", "csrf", "csp", "rebinding", "browser", "terminal"},
	{"consolidate", "consolidation", "sleep", "reflect", "reflection", "summarize", "summary", "distill", "distillation", "defrag", "inbox", "pending", "ticket", "tickets"},
	{"expiry", "expiration", "ttl", "lifetime", "recency", "decay", "temporal", "since", "before", "timeline", "history", "chronological", "window"},
}

// BuildSovereignDevPack deterministically builds a 256-dim CMVEC1 static neural concept pack
// locally with zero network access, mapping software & security engineering vocabulary onto
// shared orthogonal concept axes plus per-token lexical dimensions.
func BuildSovereignDevPack(outPath string) (string, error) {
	const dim = 256
	const conceptAxes = 128

	// Map each unique token to its concept group indices.
	tokenGroups := make(map[string][]int)
	var tokenOrder []string
	for gIdx, group := range semanticConceptGroups {
		for _, tok := range group {
			t := strings.ToLower(strings.TrimSpace(tok))
			if t == "" {
				continue
			}
			if _, seen := tokenGroups[t]; !seen {
				tokenOrder = append(tokenOrder, t)
			}
			tokenGroups[t] = append(tokenGroups[t], gIdx)
		}
	}

	vectors := make([][]float32, len(tokenOrder))
	hashEmbed := NewLocalHashEmbedder(dim - conceptAxes)

	for i, tok := range tokenOrder {
		vec := make([]float32, dim)
		// 1. Project shared semantic concept axes (first 128 dims, strong weight = 3.0)
		for _, gIdx := range tokenGroups[tok] {
			h := sha256.Sum256([]byte(fmt.Sprintf("concept-axis:%d", gIdx)))
			for k := 0; k < 8; k++ {
				slot := int(h[k*2]) % conceptAxes
				sign := float32(1.0)
				if h[k*2+1]%2 == 0 {
					sign = -1.0
				}
				vec[slot] += 3.0 * sign
			}
		}
		// 2. Project exact lexical specificity (second 128 dims, weight = 1.0)
		lex, _ := hashEmbed.Embed(context.Background(), tok)
		for j := 0; j < len(lex); j++ {
			vec[conceptAxes+j] = lex[j] * 1.1
		}
		normalize(vec)
		vectors[i] = vec
	}

	return SaveCMVEC1(outPath, dim, tokenOrder, vectors)
}

// InstallStaticModel installs a CMVEC1 pack either from the built-in offline generator,
// a local verified file, or a pinned HTTPS URL with mandatory SHA-256 verification.
func InstallStaticModel(ctx context.Context, alias, outPath, fromFile, remoteURL, expectedSHA256 string) (*StaticEmbedder, string, error) {
	if outPath == "" {
		outPath = DefaultStaticModelPath()
	}
	cleanOut := filepath.Clean(outPath)
	outDir := filepath.Dir(cleanOut)
	if fi, err := os.Lstat(outDir); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return nil, "", fmt.Errorf("%w: model directory %s is a symlink", ErrCMVEC1SymlinkRejected, outDir)
	}
	if err := os.MkdirAll(outDir, 0700); err != nil {
		return nil, "", fmt.Errorf("failed creating models dir: %w", err)
	}

	if strings.EqualFold(strings.TrimSpace(alias), "sovereign-dev-256") && fromFile == "" && remoteURL == "" {
		sum, err := BuildSovereignDevPack(cleanOut)
		if err != nil {
			return nil, "", err
		}
		emb, err := LoadStaticEmbedder(cleanOut, sum)
		return emb, sum, err
	}

	if strings.TrimSpace(fromFile) != "" {
		// Verify source pack fail-closed before copying.
		srcEmb, err := LoadStaticEmbedder(fromFile, expectedSHA256)
		if err != nil {
			return nil, "", err
		}
		data, err := os.ReadFile(fromFile)
		if err != nil {
			return nil, "", err
		}
		tmp := cleanOut + ".tmp"
		if err := os.WriteFile(tmp, data, 0600); err != nil {
			return nil, "", err
		}
		if err := os.Rename(tmp, cleanOut); err != nil {
			_ = os.Remove(tmp)
			return nil, "", err
		}
		return srcEmb, srcEmb.Checksum(), nil
	}

	if strings.TrimSpace(remoteURL) != "" {
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(remoteURL)), "https://") {
			return nil, "", fmt.Errorf("security policy violation: model pack URL must use https://")
		}
		if strings.TrimSpace(expectedSHA256) == "" {
			return nil, "", fmt.Errorf("security policy violation: --sha256 pin is mandatory when pulling remote model packs")
		}
		client := &http.Client{Timeout: 60 * time.Second}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, remoteURL, nil)
		if err != nil {
			return nil, "", err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, "", err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, "", fmt.Errorf("model download failed with HTTP %d", resp.StatusCode)
		}
		raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxCMVEC1FileBytes+1))
		if err != nil {
			return nil, "", err
		}
		if len(raw) > MaxCMVEC1FileBytes {
			return nil, "", fmt.Errorf("%w: downloaded pack exceeds %d bytes", ErrInvalidCMVEC1, MaxCMVEC1FileBytes)
		}
		sum := sha256.Sum256(raw)
		sumHex := hex.EncodeToString(sum[:])
		if sumHex != strings.ToLower(strings.TrimSpace(expectedSHA256)) {
			return nil, "", fmt.Errorf("%w: expected %s, got %s", ErrCMVEC1ChecksumMismatch, expectedSHA256, sumHex)
		}
		tmp := cleanOut + ".tmp"
		if err := os.WriteFile(tmp, raw, 0600); err != nil {
			return nil, "", err
		}
		if _, err := LoadStaticEmbedder(tmp, sumHex); err != nil {
			_ = os.Remove(tmp)
			return nil, "", err
		}
		if err := os.Rename(tmp, cleanOut); err != nil {
			_ = os.Remove(tmp)
			return nil, "", err
		}
		emb, err := LoadStaticEmbedder(cleanOut, sumHex)
		return emb, sumHex, err
	}

	return nil, "", fmt.Errorf("unknown or unconfigured model alias %q (use 'sovereign-dev-256' or pass --from-file / --url + --sha256)", alias)
}
