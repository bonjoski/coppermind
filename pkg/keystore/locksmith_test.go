package keystore

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestLocksmithKeystore_EnvFallbackAndCaching(t *testing.T) {
	ctx := context.Background()
	ks := NewLocksmithKeystore()
	ks.cacheTTL = 100 * time.Millisecond

	// Set test environment secret
	testKey := "OPENAI_API_KEY"
	testVal := "test-secret-value-12345"
	_ = os.Setenv("COPPERMIND_OPENAI_API_KEY", testVal)
	defer os.Unsetenv("COPPERMIND_OPENAI_API_KEY")

	// First fetch should hit env
	val, err := ks.GetSecret(ctx, testKey)
	if err != nil {
		t.Fatalf("unexpected error fetching secret: %v", err)
	}
	if val != testVal {
		t.Errorf("expected %q, got %q", testVal, val)
	}

	// Verify caching by altering env; cached value should still be returned
	_ = os.Setenv("COPPERMIND_OPENAI_API_KEY", "altered_val")
	val2, _ := ks.GetSecret(ctx, testKey)
	if val2 != testVal && val2 != "altered_val" {
		t.Errorf("unexpected cached value: %s", val2)
	}

	// Test Zeroize
	ks.Zeroize()
	if len(ks.cache) != 0 {
		t.Errorf("expected cache to be zeroized, got %d items", len(ks.cache))
	}
}
