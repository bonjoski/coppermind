package scratchpad

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bonjoski/coppermind/pkg/security"
)

// RedisScratchpad implements brain.Scratchpad over Redis/Dragonfly using pure-Go RESP.
type RedisScratchpad struct {
	addr string
	mu   sync.Mutex
}

// NewRedisScratchpad connects to a Redis/Dragonfly instance.
func NewRedisScratchpad(addr string) *RedisScratchpad {
	if addr == "" {
		addr = "127.0.0.1:6379"
	}
	return &RedisScratchpad{addr: addr}
}

func (r *RedisScratchpad) execute(cmd ...string) (interface{}, error) {
	conn, err := net.DialTimeout("tcp", r.addr, 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to redis at %s: %w", r.addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	// Encode RESP Array
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("*%d\r\n", len(cmd)))
	for _, arg := range cmd {
		sb.WriteString(fmt.Sprintf("$%d\r\n%s\r\n", len(arg), arg))
	}

	if _, err := conn.Write([]byte(sb.String())); err != nil {
		return nil, err
	}

	reader := bufio.NewReader(conn)
	return r.parseRESP(reader)
}

func (r *RedisScratchpad) parseRESP(reader *bufio.Reader) (interface{}, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if len(line) == 0 {
		return nil, fmt.Errorf("empty RESP line")
	}

	prefix := line[0]
	payload := line[1:]

	switch prefix {
	case '+': // Simple String
		return payload, nil
	case '-': // Error
		return nil, fmt.Errorf("redis error: %s", payload)
	case ':': // Integer
		return strconv.ParseInt(payload, 10, 64)
	case '$': // Bulk String
		length, err := strconv.Atoi(payload)
		if err != nil {
			return nil, err
		}
		if length == -1 {
			return nil, nil // Null
		}
		buf := make([]byte, length+2) // Include \r\n
		var read int
		for read < length+2 {
			n, err := reader.Read(buf[read:])
			if err != nil {
				return nil, err
			}
			read += n
		}
		return string(buf[:length]), nil
	case '*': // Array
		count, err := strconv.Atoi(payload)
		if err != nil {
			return nil, err
		}
		if count == -1 {
			return nil, nil
		}
		arr := make([]interface{}, count)
		for i := 0; i < count; i++ {
			elem, err := r.parseRESP(reader)
			if err != nil {
				return nil, err
			}
			arr[i] = elem
		}
		return arr, nil
	default:
		return nil, fmt.Errorf("unknown RESP prefix: %c", prefix)
	}
}

// Get retrieves a key from Redis.
func (r *RedisScratchpad) Get(_ context.Context, key string) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	resp, err := r.execute("GET", key)
	if err != nil || resp == nil {
		return "", false
	}
	str, ok := resp.(string)
	return str, ok
}

// Set stores a key-value pair in Redis with optional TTL.
func (r *RedisScratchpad) Set(_ context.Context, key string, val string, ttl time.Duration) error {
	secRes, err := security.SanitizeMemory(val)
	if err != nil {
		return fmt.Errorf("scratchpad write rejected: %w", err)
	}
	val = secRes.SanitizedText

	r.mu.Lock()
	defer r.mu.Unlock()

	var cmd []string
	if ttl > 0 {
		seconds := int(ttl.Seconds())
		if seconds < 1 {
			seconds = 1
		}
		cmd = []string{"SET", key, val, "EX", strconv.Itoa(seconds)}
	} else {
		cmd = []string{"SET", key, val}
	}

	_, err = r.execute(cmd...)
	return err
}

// Delete removes a key from Redis.
func (r *RedisScratchpad) Delete(_ context.Context, key string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	_, err := r.execute("DEL", key)
	return err
}

// AcquireLock implements distributed mutex locking via Redis SET NX EX.
func (r *RedisScratchpad) AcquireLock(_ context.Context, lockName string, ttl time.Duration) (func(), error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	seconds := int(ttl.Seconds())
	if seconds < 1 {
		seconds = 1
	}

	tokenBytes := make([]byte, 16)
	_, _ = rand.Read(tokenBytes)
	token := hex.EncodeToString(tokenBytes)

	resp, err := r.execute("SET", "lock:"+lockName, token, "NX", "EX", strconv.Itoa(seconds))
	if err != nil {
		return nil, fmt.Errorf("failed to acquire lock: %w", err)
	}
	if resp == nil {
		return nil, fmt.Errorf("lock %q is already held by another agent", lockName)
	}

	unlock := func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		_, _ = r.execute("DEL", "lock:"+lockName)
	}

	return unlock, nil
}

// Keys returns all keys matching a pattern.
func (r *RedisScratchpad) Keys(_ context.Context) []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	resp, err := r.execute("KEYS", "*")
	if err != nil || resp == nil {
		return nil
	}

	arr, ok := resp.([]interface{})
	if !ok {
		return nil
	}

	keys := make([]string, 0, len(arr))
	for _, item := range arr {
		if s, ok := item.(string); ok {
			if !strings.HasPrefix(s, "lock:") {
				keys = append(keys, s)
			}
		}
	}
	return keys
}
