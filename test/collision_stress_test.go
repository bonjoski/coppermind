package test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bonjoski/coppermind/pkg/authz"
	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/embedding"
	"github.com/bonjoski/coppermind/pkg/scratchpad"
	"github.com/bonjoski/coppermind/pkg/storage"
	"github.com/bonjoski/coppermind/pkg/storage/postgres"
	"github.com/bonjoski/coppermind/pkg/storage/sqlite"
	"github.com/bonjoski/coppermind/pkg/watcher"
)

// TestCollision_ProfileA_SQLiteAndMemoryScratchpad exercises N=8 parallel agents colliding on
// the exact same session, memory nodes, graph entities, inbox tickets, supersession target,
// vault watcher directory, vector reindexing, and scratchpad CAS/locks on Profile A (SQLite).
func TestCollision_ProfileA_SQLiteAndMemoryScratchpad(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := sqlite.NewSQLiteStore(filepath.Join(tmpDir, "collision_a.db"))
	if err != nil {
		t.Fatalf("failed opening sqlite store: %v", err)
	}
	defer store.Close()

	emb := embedding.NewLocalHashEmbedder(128)
	sp := scratchpad.NewMemoryScratchpad()
	mgr := brain.NewManager(store, emb, sp)
	defer mgr.Close()

	runSharedCollisionHarness(t, mgr, store, sp, "profA")
}

// TestCollision_ProfileB_PostgresAndRedisScratchpad runs the exact same N=8 collision suite
// against Profile B (PostgreSQL 17 + pgvector + Redis/Dragonfly RESP scratchpad).
// Skips only if COPPERMIND_POSTGRES_URL is unset.
func TestCollision_ProfileB_PostgresAndRedisScratchpad(t *testing.T) {
	pgURL := os.Getenv("COPPERMIND_POSTGRES_URL")
	if pgURL == "" {
		t.Skip("Skipping live Profile B collision test (set COPPERMIND_POSTGRES_URL to execute against PostgreSQL)")
	}
	ctx := context.Background()
	emb := embedding.NewLocalHashEmbedder(128)
	store, err := postgres.NewPostgresStore(ctx, postgres.Config{
		URL:       pgURL,
		Dimension: emb.Dimension(),
	})
	if err != nil {
		t.Fatalf("failed opening postgres store: %v", err)
	}
	defer store.Close()

	redisAddr := os.Getenv("COPPERMIND_REDIS_ADDR")
	var stopMock func()
	if redisAddr == "" {
		redisAddr, stopMock = startInProcessMockRESP(t)
		defer stopMock()
	}
	sp := scratchpad.NewRedisScratchpad(redisAddr)
	mgr := brain.NewManager(store, emb, sp)
	defer mgr.Close()

	prefix := fmt.Sprintf("profB_%d", time.Now().UnixNano())
	runSharedCollisionHarness(t, mgr, store, sp, prefix)
}

func runSharedCollisionHarness(t *testing.T, mgr *brain.Manager, store brain.MemoryStore, sp brain.Scratchpad, prefix string) {
	t.Helper()
	ctx := context.Background()
	const agents = 8

	// -------------------------------------------------------------------------
	// Phase 1: N=8 Shared-Session Concurrent Appends -> Cryptographic Merkle Chain Integrity
	// -------------------------------------------------------------------------
	sharedSession := prefix + "_merkle_shared"
	const writesPerAgent = 10
	{
		var startGate sync.WaitGroup
		startGate.Add(1)
		var wg sync.WaitGroup
		errCh := make(chan error, agents*writesPerAgent)

		for a := 0; a < agents; a++ {
			wg.Add(1)
			go func(agentID int) {
				defer wg.Done()
				startGate.Wait()
				for i := 0; i < writesPerAgent; i++ {
					_, err := mgr.Remember(ctx, brain.RememberRequest{
						SessionID: sharedSession,
						Category:  "architecture",
						Content:   fmt.Sprintf("Shared session event agent=%d seq=%d touching pkg/mcp/server.go", agentID, i),
						Metadata:  map[string]string{"git_repo": prefix},
					})
					if err != nil {
						errCh <- fmt.Errorf("phase1 agent=%d seq=%d: %w", agentID, i, err)
					}
				}
			}(a)
		}
		startGate.Done()
		wg.Wait()
		close(errCh)
		for err := range errCh {
			t.Fatalf("Phase 1 shared-session write error: %v", err)
		}

		ok, cnt, badID, err := mgr.VerifySessionChain(ctx, sharedSession)
		if err != nil || !ok || cnt != agents*writesPerAgent {
			t.Fatalf("COLLISION FAILURE (Merkle fork): ok=%t cnt=%d (want %d) badID=%q err=%v",
				ok, cnt, agents*writesPerAgent, badID, err)
		}
		t.Logf("✓ Phase 1 [%s]: %d concurrent shared-session writes verified intact Merkle chain", prefix, cnt)
	}

	// -------------------------------------------------------------------------
	// Phase 2: N=8 Simultaneous Mixed Read + Add + Delete + Graph + Inbox + Reindex Chaos
	// -------------------------------------------------------------------------
	{
		chaosSession := prefix + "_chaos"
		var wg sync.WaitGroup
		errCh := make(chan error, 512)

		inboxStore, _ := store.(storage.InboxStore)
		graphStore, _ := store.(storage.GraphStore)
		expStore, _ := store.(storage.ExplorerStore)
		vecStore, _ := store.(storage.VectorAdminStore)

		for a := 0; a < agents; a++ {
			wg.Add(1)
			go func(agentID int) {
				defer wg.Done()
				for i := 0; i < 8; i++ {
					// Add a node
					n, err := mgr.Remember(ctx, brain.RememberRequest{
						SessionID: chaosSession,
						Category:  "note",
						Content:   fmt.Sprintf("Chaos node agent=%d iter=%d referencing pkg/mcp/server.go and RFC-2026-11-24-57", agentID, i),
						Metadata:  map[string]string{"git_repo": prefix},
					})
					if err != nil {
						errCh <- fmt.Errorf("chaos remember agent=%d: %w", agentID, err)
						return
					}

					// Concurrent Hybrid + 1-hop Graph recall
					if _, err := mgr.Recall(ctx, brain.RecallRequest{
						Query:  "pkg/mcp/server.go RFC-2026-11-24-57",
						Hybrid: true,
						Hops:   1,
						Limit:  5,
					}); err != nil {
						errCh <- fmt.Errorf("chaos recall agent=%d: %w", agentID, err)
						return
					}

					// Concurrent Inbox ticket collision (same memory_id + lens deduplicated cleanly)
					if inboxStore != nil {
						_ = inboxStore.EnqueuePendingTicket(ctx, storage.PendingLensTicket{
							LensName: "security-architect",
							MemoryID: n.ID,
							RepoName: prefix,
							Summary:  fmt.Sprintf("chaos ticket %d-%d", agentID, i),
						})
						_, _ = inboxStore.ListPendingTickets(ctx, "security-architect", "pending", 10)
					}

					// Concurrent Graph & Timeline reads
					if graphStore != nil {
						_, _, _ = graphStore.GetGraphSubgraph(ctx, n.ID, 15, 30)
					}
					if expStore != nil {
						_, _ = expStore.ListTimeline(ctx, storage.TimelineFilter{Repo: prefix, Limit: 10})
					}

					// Delete every even-iteration node while peers are actively reading/writing
					if i%2 == 0 {
						if err := store.Delete(ctx, n.ID); err != nil {
							errCh <- fmt.Errorf("chaos delete agent=%d id=%s: %w", agentID, n.ID, err)
							return
						}
					}
				}
			}(a)
		}

		// Concurrent background ReindexVectors dry-run + live pass while agents hammer DB
		if vecStore != nil {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for k := 0; k < 2; k++ {
					if _, err := vecStore.ReindexVectors(ctx, mgr.Embedder(), mgr.EmbedderModelName(), 32, false); err != nil {
						errCh <- fmt.Errorf("chaos reindex pass %d: %w", k, err)
						return
					}
				}
			}()
		}

		wg.Wait()
		close(errCh)
		for err := range errCh {
			t.Fatalf("Phase 2 mixed read/write/delete chaos error: %v", err)
		}
		t.Logf("✓ Phase 2 [%s]: N=8 mixed read/add/delete/graph/inbox/reindex completed with zero contention errors", prefix)
	}

	// -------------------------------------------------------------------------
	// Phase 3: N=8 Supersession Collision Race on the EXACT SAME Target Node
	// -------------------------------------------------------------------------
	{
		target, err := mgr.Remember(ctx, brain.RememberRequest{
			SessionID:     prefix + "_supersede",
			Category:      "architecture",
			Content:       "Original invariant v1 subject to N=8 supersession race.",
			AuthorityTier: authz.TierName1Architecture,
		})
		if err != nil {
			t.Fatalf("seed target for supersession race failed: %v", err)
		}

		var startGate sync.WaitGroup
		startGate.Add(1)
		var wg sync.WaitGroup
		var winners atomic.Int32
		var rejected atomic.Int32
		var winnerID atomic.Value

		for a := 0; a < agents; a++ {
			wg.Add(1)
			go func(agentID int) {
				defer wg.Done()
				startGate.Wait()
				n, sErr := mgr.Remember(ctx, brain.RememberRequest{
					SessionID:     prefix + "_supersede",
					Category:      "architecture",
					Content:       fmt.Sprintf("Superseding invariant v2 from agent=%d", agentID),
					AuthorityTier: authz.TierName1Architecture,
					SupersedesID:  target.ID,
					Rationale:     fmt.Sprintf("Agent %d supersession race", agentID),
				})
				if sErr == nil {
					winners.Add(1)
					winnerID.Store(n.ID)
				} else {
					rejected.Add(1)
				}
			}(a)
		}
		startGate.Done()
		wg.Wait()

		if winners.Load() != 1 || rejected.Load() != agents-1 {
			t.Fatalf("COLLISION FAILURE (double-supersede race): expected strictly 1 winner and %d rejected, got winners=%d rejected=%d",
				agents-1, winners.Load(), rejected.Load())
		}
		targetAfter, err := store.GetByID(ctx, target.ID)
		if err != nil || targetAfter.LifecycleStatus != string(authz.StatusSuperseded) || targetAfter.SupersededByID != winnerID.Load().(string) {
			t.Fatalf("post-race target state inconsistent: %+v err=%v", targetAfter, err)
		}
		t.Logf("✓ Phase 3 [%s]: N=8 supersession race produced strictly 1 winner (%s) and %d fail-closed rejections",
			prefix, winnerID.Load().(string), rejected.Load())
	}

	// -------------------------------------------------------------------------
	// Phase 4: Concurrent Read-Only Vault Watcher Syncs on the Same Directory
	// -------------------------------------------------------------------------
	{
		vaultDir := filepath.Join(t.TempDir(), prefix+"_vault")
		_ = os.MkdirAll(vaultDir, 0700)
		for i := 0; i < 4; i++ {
			_ = os.WriteFile(filepath.Join(vaultDir, fmt.Sprintf("note-%d.md", i)),
				[]byte(fmt.Sprintf("---\ntitle: Note %d\n---\nLinks to [[Note %d]].\n", i, (i+1)%4)), 0600)
		}
		var wg sync.WaitGroup
		errCh := make(chan error, 4)
		for w := 0; w < 4; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := watcher.SyncVaultOnce(ctx, mgr, vaultDir, watcher.Options{Category: "note"}); err != nil {
					errCh <- err
				}
			}()
		}
		wg.Wait()
		close(errCh)
		for err := range errCh {
			t.Fatalf("Phase 4 concurrent vault watcher error: %v", err)
		}
		t.Logf("✓ Phase 4 [%s]: 4 concurrent vault watcher syncs converged cleanly", prefix)
	}

	// -------------------------------------------------------------------------
	// Phase 5: Scratchpad N=8 Atomic CAS & Distributed Lock Collision Race
	// -------------------------------------------------------------------------
	if casSp, ok := mgr.Scratchpad().(scratchpad.CASScratchpad); ok {
		key := scratchpad.HandoffKey(prefix + "_race")
		var startGate sync.WaitGroup
		startGate.Add(1)
		var wg sync.WaitGroup
		var casWins atomic.Int32
		for a := 0; a < agents; a++ {
			wg.Add(1)
			go func(agentID int) {
				defer wg.Done()
				startGate.Wait()
				pkt, _ := scratchpad.EncodeHandoff(scratchpad.HandoffPacket{
					AgentID:  fmt.Sprintf("agent-%d", agentID),
					Worktree: prefix,
					Goal:     "CAS collision winner",
					NextStep: "continue",
				})
				if swapped, err := casSp.CompareAndSwap(ctx, key, "", pkt, 60*time.Second); err == nil && swapped {
					casWins.Add(1)
				}
			}(a)
		}
		startGate.Done()
		wg.Wait()
		if casWins.Load() != 1 {
			t.Fatalf("COLLISION FAILURE (scratchpad CAS): expected strictly 1 winner across N=%d, got %d", agents, casWins.Load())
		}
		_ = sp.Delete(ctx, key)

		// Distributed lock race: strictly 1 holder at a time
		lockName := prefix + "_lock"
		var lockGate sync.WaitGroup
		lockGate.Add(1)
		var lockWins atomic.Int32
		var unlockFn atomic.Value
		for a := 0; a < agents; a++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				lockGate.Wait()
				if u, err := sp.AcquireLock(ctx, lockName, 30*time.Second); err == nil && u != nil {
					lockWins.Add(1)
					unlockFn.Store(u)
				}
			}()
		}
		lockGate.Done()
		wg.Wait()
		if lockWins.Load() != 1 {
			t.Fatalf("COLLISION FAILURE (AcquireLock): expected strictly 1 lock winner across N=%d, got %d", agents, lockWins.Load())
		}
		if fn, ok := unlockFn.Load().(func()); ok && fn != nil {
			fn()
		}
		t.Logf("✓ Phase 5 [%s]: N=8 Scratchpad CAS & AcquireLock races each produced strictly 1 winner", prefix)
	}
}

// startInProcessMockRESP spins up a thread-safe minimal RESP server supporting GET, SET (NX/EX),
// DEL, KEYS, and EVAL (CAS & token-checked unlock) so Profile B Redis tests run deterministically
// even when no standalone Redis daemon is listening on localhost:6379.
func startInProcessMockRESP(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	kv := make(map[string]string)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				rd := bufio.NewReader(c)
				line, err := rd.ReadString('\n')
				if err != nil || !strings.HasPrefix(line, "*") {
					return
				}
				nArgs, _ := strconv.Atoi(strings.TrimSpace(line[1:]))
				args := make([]string, 0, nArgs)
				for i := 0; i < nArgs; i++ {
					hdr, err := rd.ReadString('\n')
					if err != nil || !strings.HasPrefix(hdr, "$") {
						return
					}
					sz, _ := strconv.Atoi(strings.TrimSpace(hdr[1:]))
					buf := make([]byte, sz+2)
					read := 0
					for read < len(buf) {
						n, rErr := rd.Read(buf[read:])
						if rErr != nil {
							return
						}
						read += n
					}
					args = append(args, string(buf[:sz]))
				}
				if len(args) == 0 {
					return
				}
				switch strings.ToUpper(args[0]) {
				case "GET":
					mu.Lock()
					v, ok := kv[args[1]]
					mu.Unlock()
					if !ok {
						_, _ = c.Write([]byte("$-1\r\n"))
					} else {
						_, _ = fmt.Fprintf(c, "$%d\r\n%s\r\n", len(v), v)
					}
				case "SET":
					key, val := args[1], args[2]
					nx := false
					for _, opt := range args[3:] {
						if strings.EqualFold(opt, "NX") {
							nx = true
						}
					}
					mu.Lock()
					_, exists := kv[key]
					if nx && exists {
						mu.Unlock()
						_, _ = c.Write([]byte("$-1\r\n"))
						return
					}
					kv[key] = val
					mu.Unlock()
					_, _ = c.Write([]byte("+OK\r\n"))
				case "DEL":
					mu.Lock()
					delete(kv, args[1])
					mu.Unlock()
					_, _ = c.Write([]byte(":1\r\n"))
				case "KEYS":
					mu.Lock()
					keys := make([]string, 0, len(kv))
					for k := range kv {
						keys = append(keys, k)
					}
					mu.Unlock()
					_, _ = fmt.Fprintf(c, "*%d\r\n", len(keys))
					for _, k := range keys {
						_, _ = fmt.Fprintf(c, "$%d\r\n%s\r\n", len(k), k)
					}
				case "EVAL":
					script := args[1]
					key := args[3]
					mu.Lock()
					if strings.Contains(script, "redis.call('DEL'") {
						// Token-checked unlock
						token := args[4]
						if kv[key] == token {
							delete(kv, key)
							mu.Unlock()
							_, _ = c.Write([]byte(":1\r\n"))
						} else {
							mu.Unlock()
							_, _ = c.Write([]byte(":0\r\n"))
						}
					} else {
						// CAS script
						expected, newVal := args[4], args[5]
						if kv[key] == expected {
							kv[key] = newVal
							mu.Unlock()
							_, _ = c.Write([]byte(":1\r\n"))
						} else {
							mu.Unlock()
							_, _ = c.Write([]byte(":0\r\n"))
						}
					}
				}
			}(conn)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}
