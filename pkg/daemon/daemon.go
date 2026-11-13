package daemon

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/mcp"
	"github.com/bonjoski/coppermind/pkg/queue"
	"github.com/bonjoski/coppermind/pkg/worker"
)

// Config defines network and file locations for the Coppermind daemon.
type Config struct {
	SocketPath string
	TCPAddr    string
}

// Daemon manages background listeners accepting MCP connections over Unix Domain Sockets and TCP.
type Daemon struct {
	cfg         Config
	manager     *brain.Manager
	broker      queue.Broker
	worker      *worker.CognitiveWorker
	udsListener net.Listener
	tcpListener net.Listener
	stopCh      chan struct{}
	wg          sync.WaitGroup
	mu          sync.Mutex
	isClosed    bool
}

// NewDaemon initializes a new multi-tenant listener daemon.
func NewDaemon(cfg Config, mgr *brain.Manager, broker queue.Broker, w *worker.CognitiveWorker) *Daemon {
	return &Daemon{
		cfg:     cfg,
		manager: mgr,
		broker:  broker,
		worker:  w,
		stopCh:  make(chan struct{}),
	}
}

// Start opens the listeners and dispatches connection workers.
func (d *Daemon) Start(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// 1. Unix Domain Socket Listener
	if d.cfg.SocketPath != "" {
		_ = os.MkdirAll(filepath.Dir(d.cfg.SocketPath), 0700)
		_ = os.Remove(d.cfg.SocketPath) // Clean up any stale socket

		l, err := net.Listen("unix", d.cfg.SocketPath)
		if err != nil {
			return fmt.Errorf("failed to bind unix socket at %s: %w", d.cfg.SocketPath, err)
		}
		_ = os.Chmod(d.cfg.SocketPath, 0600)
		d.udsListener = l

		d.wg.Add(1)
		go d.acceptLoop(ctx, l)
	}

	// 2. Optional TCP Listener
	if d.cfg.TCPAddr != "" {
		l, err := net.Listen("tcp", d.cfg.TCPAddr)
		if err != nil {
			if d.udsListener != nil {
				_ = d.udsListener.Close()
			}
			return fmt.Errorf("failed to bind tcp listener at %s: %w", d.cfg.TCPAddr, err)
		}
		d.tcpListener = l

		d.wg.Add(1)
		go d.acceptLoop(ctx, l)
	}

	return nil
}

func (d *Daemon) acceptLoop(ctx context.Context, l net.Listener) {
	defer d.wg.Done()

	for {
		conn, err := l.Accept()
		if err != nil {
			select {
			case <-d.stopCh:
				return
			default:
				time.Sleep(10 * time.Millisecond)
				continue
			}
		}

		d.wg.Add(1)
		go func(c net.Conn) {
			defer d.wg.Done()
			defer c.Close()

			server := mcp.NewServer(d.manager, c)
			if d.broker != nil && d.worker != nil {
				server.SetWorker(d.broker, d.worker)
			}
			_ = server.ServeStream(ctx, c, c)
		}(conn)
	}
}

// Stop gracefully shuts down listeners and removes the unix socket file.
func (d *Daemon) Stop() error {
	d.mu.Lock()
	if d.isClosed {
		d.mu.Unlock()
		return nil
	}
	d.isClosed = true
	close(d.stopCh)

	if d.udsListener != nil {
		_ = d.udsListener.Close()
	}
	if d.tcpListener != nil {
		_ = d.tcpListener.Close()
	}
	d.mu.Unlock()

	d.wg.Wait()

	if d.cfg.SocketPath != "" {
		_ = os.Remove(d.cfg.SocketPath)
	}

	return nil
}
