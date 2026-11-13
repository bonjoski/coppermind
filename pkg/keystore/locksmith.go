package keystore

import (
	"context"
	"fmt"
	"os"
	"os/exec"
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
	locksmithBin string
}

type cachedSecret struct {
	value     string
	expiresAt time.Time
}

// NewLocksmithKeystore creates a new hardware keystore integration.
func NewLocksmithKeystore() *LocksmithKeystore {
	bin, _ := exec.LookPath("locksmith")
	return &LocksmithKeystore{
		cache:        make(map[string]cachedSecret),
		cacheTTL:     5 * time.Minute, // Amortized lease window
		locksmithBin: bin,
	}
}

// GetSecret fetches a secret from Locksmith (Touch ID/TPM2) with in-memory lease amortization.
func (k *LocksmithKeystore) GetSecret(ctx context.Context, key string) (string, error) {
	// 1. Check in-memory amortized lease cache (avoids repeated biometric prompts)
	k.mu.RLock()
	item, ok := k.cache[key]
	if ok && time.Now().Before(item.expiresAt) {
		k.mu.RUnlock()
		return item.value, nil
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

	// 3. Query Locksmith CLI if available
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

	// Cache secret in-memory for the duration of the session window
	k.mu.Lock()
	k.cache[key] = cachedSecret{
		value:     secret,
		expiresAt: time.Now().Add(k.cacheTTL),
	}
	k.mu.Unlock()

	return secret, nil
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
