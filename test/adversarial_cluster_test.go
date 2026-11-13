package test

import (
	"context"
	"testing"
	"time"

	"github.com/bonjoski/coppermind/pkg/scratchpad"
	"github.com/bonjoski/coppermind/pkg/storage/postgres"
)

func TestADV_ClusterPostgres_MalformedEndpointFailsClosed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// 1. Attempt to connect to non-routable / invalid postgres URI
	_, err := postgres.NewPostgresStore(ctx, postgres.Config{
		URL:       "postgres://invalid_user:invalid_pass@127.0.0.1:59999/coppermind?sslmode=disable&connect_timeout=1",
		Dimension: 128,
	})
	if err == nil {
		t.Fatalf("expected fail-closed error connecting to invalid PostgreSQL cluster, got nil")
	}
}

func TestADV_ClusterRedis_ConnectionRefusedFailsClosed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// 2. Attempt to use Redis on non-existent port
	sp := scratchpad.NewRedisScratchpad("127.0.0.1:59998")

	// Get should return false without panic
	val, ok := sp.Get(ctx, "any_key")
	if ok || val != "" {
		t.Errorf("expected Get on unreachable Redis to return false, got %q (ok=%v)", val, ok)
	}

	// Set should return error
	err := sp.Set(ctx, "any_key", "val", 1*time.Minute)
	if err == nil {
		t.Errorf("expected Set on unreachable Redis to fail, got nil")
	}

	// Lock should return error
	_, err = sp.AcquireLock(ctx, "any_lock", 1*time.Minute)
	if err == nil {
		t.Errorf("expected AcquireLock on unreachable Redis to fail, got nil")
	}
}
