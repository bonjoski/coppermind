package daemon_test

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/daemon"
	"github.com/bonjoski/coppermind/pkg/embedding"
	"github.com/bonjoski/coppermind/pkg/mcp"
	"github.com/bonjoski/coppermind/pkg/scratchpad"
	"github.com/bonjoski/coppermind/pkg/storage/sqlite"
)

func TestDaemon_UnixDomainSocket(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "daemon_test.db")
	sockPath := filepath.Join(tmpDir, "test.sock")

	store, err := sqlite.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to init store: %v", err)
	}
	defer store.Close()

	embedder := embedding.NewLocalHashEmbedder(128)
	sp := scratchpad.NewMemoryScratchpad()
	mgr := brain.NewManager(store, embedder, sp)

	d := daemon.NewDaemon(daemon.Config{
		SocketPath: sockPath,
	}, mgr, nil, nil)

	if err := d.Start(ctx); err != nil {
		t.Fatalf("failed to start daemon: %v", err)
	}
	defer d.Stop()

	// Connect to Unix domain socket
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to dial unix socket: %v", err)
	}
	defer conn.Close()

	scanner := bufio.NewScanner(conn)

	// 1. Send initialize
	initReq := mcp.JSONRPCMessage{
		JSONRPC: "2.0",
		ID:      json.RawMessage("1"),
		Method:  "initialize",
		Params:  json.RawMessage(`{"protocolVersion":"2024-11-05"}`),
	}
	data, _ := json.Marshal(initReq)
	_, _ = conn.Write(append(data, '\n'))

	if !scanner.Scan() {
		t.Fatalf("expected response from daemon, got none")
	}

	var initResp mcp.JSONRPCMessage
	if err := json.Unmarshal(scanner.Bytes(), &initResp); err != nil {
		t.Fatalf("failed to decode init response: %v", err)
	}
	if initResp.Error != nil {
		t.Fatalf("unexpected init error: %v", initResp.Error)
	}

	// 2. Call coppermind_remember over UDS socket
	callReq := mcp.JSONRPCMessage{
		JSONRPC: "2.0",
		ID:      json.RawMessage("2"),
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"coppermind_remember","arguments":{"content":"UDS socket memory test","category":"architecture"}}`),
	}
	data, _ = json.Marshal(callReq)
	_, _ = conn.Write(append(data, '\n'))

	if !scanner.Scan() {
		t.Fatalf("expected response for tool call, got none")
	}

	var callResp mcp.JSONRPCMessage
	if err := json.Unmarshal(scanner.Bytes(), &callResp); err != nil {
		t.Fatalf("failed to decode tool call response: %v", err)
	}
	if callResp.Error != nil {
		t.Fatalf("tool call returned error: %v", callResp.Error)
	}

	// 3. Verify memory stored in SQLite
	count, err := mgr.Count(ctx, "")
	if err != nil || count != 1 {
		t.Errorf("expected 1 memory in database, got %d (err: %v)", count, err)
	}
}

func TestDaemon_TCPListener(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "tcp_daemon.db")

	store, err := sqlite.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to init store: %v", err)
	}
	defer store.Close()

	embedder := embedding.NewLocalHashEmbedder(128)
	sp := scratchpad.NewMemoryScratchpad()
	mgr := brain.NewManager(store, embedder, sp)

	d := daemon.NewDaemon(daemon.Config{
		TCPAddr: "127.0.0.1:0", // ephemeral port
	}, mgr, nil, nil)

	if err := d.Start(ctx); err != nil {
		t.Fatalf("failed to start daemon: %v", err)
	}
	defer d.Stop()

	// Give listener a moment to bind
	time.Sleep(10 * time.Millisecond)
}
