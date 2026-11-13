package keystore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Keystore defines the contract for retrieving hardware-backed secrets.
type Keystore interface {
	GetSecret(ctx context.Context, key string) (string, error)
	ListSecrets(ctx context.Context) ([]string, error)
}

// LocksmithKeystore retrieves secrets directly from Locksmith hardware vault or ambient env.
type LocksmithKeystore struct {
	mu           sync.RWMutex
	cache        map[string]cachedSecret
	cacheTTL     time.Duration
	leaseDir     string
	locksmithBin string
}

type cachedSecret struct {
	Value     string    `json:"value"`
	ExpiresAt time.Time `json:"expires_at"`
}

// NewLocksmithKeystore creates a new hardware keystore integration.
func NewLocksmithKeystore() *LocksmithKeystore {
	bin, _ := exec.LookPath("locksmith")
	home, err := os.UserHomeDir()
	leaseDir := ""
	if err == nil {
		leaseDir = filepath.Join(home, ".coppermind", "leases")
		_ = os.MkdirAll(leaseDir, 0700)
	}

	return &LocksmithKeystore{
		cache:        make(map[string]cachedSecret),
		cacheTTL:     4 * time.Hour, // 4-hour persistent lease window to avoid biometric stalls
		leaseDir:     leaseDir,
		locksmithBin: bin,
	}
}

// GetSecret fetches a secret from Locksmith (Touch ID/TPM2) with multi-hour lease amortization.
func (k *LocksmithKeystore) GetSecret(ctx context.Context, key string) (string, error) {
	// 1. Check in-memory amortized lease cache
	k.mu.RLock()
	item, ok := k.cache[key]
	if ok && time.Now().Before(item.ExpiresAt) {
		k.mu.RUnlock()
		return item.Value, nil
	}
	k.mu.RUnlock()

	// 2. Check ambient environment fallback (e.g. COPPERMIND_OPENAI_API_KEY)
	envKey := "COPPERMIND_" + strings.ToUpper(strings.ReplaceAll(key, "-", "_"))
	if envVal := os.Getenv(envKey); envVal != "" {
		return envVal, nil
	}
	// Direct env key fallback
	if envVal := os.Getenv(key); envVal != "" {
		return envVal, nil
	}

	// 3. Check persistent disk lease cache (survives process restarts across CLI tools)
	if k.leaseDir != "" {
		leasePath := k.getLeasePath(key)
		if data, err := os.ReadFile(leasePath); err == nil {
			var diskLease cachedSecret
			if err := json.Unmarshal(data, &diskLease); err == nil {
				if time.Now().Before(diskLease.ExpiresAt) && diskLease.Value != "" {
					k.mu.Lock()
					k.cache[key] = diskLease
					k.mu.Unlock()
					return diskLease.Value, nil
				}
			}
		}
	}

	// 4. Query Locksmith CLI if available (triggers biometric authorization)
	if k.locksmithBin == "" {
		return "", fmt.Errorf("locksmith binary not found in PATH and %s is unset", envKey)
	}

	cmd := exec.CommandContext(ctx, k.locksmithBin, "get", key)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("locksmith secret retrieval failed for %q: %w", key, err)
	}

	secret := strings.TrimSpace(string(out))
	if secret == "" {
		return "", fmt.Errorf("secret %q not found in Locksmith", key)
	}

	// Cache secret in-memory and write mode 0600 disk lease file
	lease := cachedSecret{
		Value:     secret,
		ExpiresAt: time.Now().Add(k.cacheTTL),
	}

	k.mu.Lock()
	k.cache[key] = lease
	k.mu.Unlock()

	if k.leaseDir != "" {
		leasePath := k.getLeasePath(key)
		if data, err := json.Marshal(lease); err == nil {
			_ = os.WriteFile(leasePath, data, 0600)
		}
	}

	return secret, nil
}

func (k *LocksmithKeystore) getLeasePath(key string) string {
	h := sha256.Sum256([]byte(key))
	filename := fmt.Sprintf("lease_%s.json", hex.EncodeToString(h[:8]))
	return filepath.Join(k.leaseDir, filename)
}

// ListSecrets retrieves list of stored keys from Locksmith.
func (k *LocksmithKeystore) ListSecrets(ctx context.Context) ([]string, error) {
	if k.locksmithBin == "" {
		return nil, fmt.Errorf("locksmith binary not found")
	}

	cmd := exec.CommandContext(ctx, k.locksmithBin, "list")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var keys []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			keys = append(keys, l)
		}
	}
	return keys, nil
}

// Zeroize wipes all cached secret values from memory.
func (k *LocksmithKeystore) Zeroize() {
	k.mu.Lock()
	defer k.mu.Unlock()
	for kVal := range k.cache {
		delete(k.cache, kVal)
	}
}
