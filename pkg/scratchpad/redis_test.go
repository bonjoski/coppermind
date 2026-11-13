package scratchpad

import (
	"bufio"
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestRESPParsing(t *testing.T) {
	r := &RedisScratchpad{}

	// 1. Simple string
	reader := bufio.NewReader(strings.NewReader("+OK\r\n"))
	res, err := r.parseRESP(reader)
	if err != nil || res != "OK" {
		t.Fatalf("expected 'OK', got %v (err: %v)", res, err)
	}

	// 2. Integer
	reader = bufio.NewReader(strings.NewReader(":1024\r\n"))
	res, err = r.parseRESP(reader)
	if err != nil || res != int64(1024) {
		t.Fatalf("expected 1024, got %v (err: %v)", res, err)
	}

	// 3. Bulk string
	reader = bufio.NewReader(strings.NewReader("$11\r\nhello world\r\n"))
	res, err = r.parseRESP(reader)
	if err != nil || res != "hello world" {
		t.Fatalf("expected 'hello world', got %v (err: %v)", res, err)
	}

	// 4. Null bulk string
	reader = bufio.NewReader(strings.NewReader("$-1\r\n"))
	res, err = r.parseRESP(reader)
	if err != nil || res != nil {
		t.Fatalf("expected nil, got %v (err: %v)", res, err)
	}

	// 5. Array
	reader = bufio.NewReader(strings.NewReader("*2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n"))
	res, err = r.parseRESP(reader)
	if err != nil {
		t.Fatalf("parse array failed: %v", err)
	}
	arr, ok := res.([]interface{})
	if !ok || len(arr) != 2 || arr[0] != "foo" || arr[1] != "bar" {
		t.Fatalf("unexpected array result: %+v", res)
	}
}

func TestRedisScratchpad_LiveIntegration(t *testing.T) {
	redisAddr := os.Getenv("COPPERMIND_REDIS_ADDR")
	if redisAddr == "" {
		t.Skip("Skipping live Redis integration test (COPPERMIND_REDIS_ADDR unset)")
	}

	ctx := context.Background()
	sp := NewRedisScratchpad(redisAddr)

	key := "test_key_" + time.Now().Format("150405")
	if err := sp.Set(ctx, key, "sample_value", 10*time.Second); err != nil {
		t.Fatalf("failed to set key in redis: %v", err)
	}

	val, ok := sp.Get(ctx, key)
	if !ok || val != "sample_value" {
		t.Fatalf("expected 'sample_value', got %q (ok=%v)", val, ok)
	}

	_ = sp.Delete(ctx, key)
}
