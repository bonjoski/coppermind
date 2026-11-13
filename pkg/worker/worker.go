package worker

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/indexer"
	"github.com/bonjoski/coppermind/pkg/queue"
	"github.com/bonjoski/coppermind/pkg/router"
)

// WorkerMetrics tracks background execution health and volume.
type WorkerMetrics struct {
	TasksProcessed uint64
	TasksFailed    uint64
	LastTaskTime   time.Time
}

// CognitiveWorker orchestrates asynchronous background reflection and maintenance.
type CognitiveWorker struct {
	broker     queue.Broker
	manager    *brain.Manager
	router     router.ModelRouter
	metrics    WorkerMetrics
	mu         sync.RWMutex
	wg         sync.WaitGroup
	stopCh     chan struct{}
	cancelFunc context.CancelFunc
}

// NewCognitiveWorker instantiates a new worker.
func NewCognitiveWorker(broker queue.Broker, manager *brain.Manager, modelRouter router.ModelRouter) *CognitiveWorker {
	return &CognitiveWorker{
		broker:  broker,
		manager: manager,
		router:  modelRouter,
		stopCh:  make(chan struct{}),
	}
}

// Start registers subscriptions on the message broker and processes incoming tasks.
func (w *CognitiveWorker) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	w.cancelFunc = cancel

	// Subscribe to all cognitive tasks
	err := w.broker.Subscribe(ctx, "#", func(taskCtx context.Context, task *queue.TaskEnvelope) error {
		return w.processTask(taskCtx, task)
	})
	if err != nil {
		return fmt.Errorf("failed to register worker subscription: %w", err)
	}

	return nil
}

func (w *CognitiveWorker) processTask(ctx context.Context, task *queue.TaskEnvelope) error {
	w.wg.Add(1)
	defer w.wg.Done()

	w.mu.Lock()
	w.metrics.LastTaskTime = time.Now()
	w.mu.Unlock()

	var err error
	switch task.Type {
	case queue.TaskSummarizeSession, queue.TaskDeepReflect:
		err = w.handleReflection(ctx, task)
	case queue.TaskExtractDecisions:
		err = w.handleExtractDecisions(ctx, task)
	case queue.TaskIndexGitTree:
		err = w.handleIndexGitTree(ctx, task)
	case queue.TaskDefragMemory:
		err = w.handleDefrag(ctx)
	default:
		err = fmt.Errorf("unsupported task type: %s", task.Type)
	}

	if err != nil {
		atomic.AddUint64(&w.metrics.TasksFailed, 1)
		return err
	}

	atomic.AddUint64(&w.metrics.TasksProcessed, 1)
	return nil
}

func (w *CognitiveWorker) handleReflection(ctx context.Context, task *queue.TaskEnvelope) error {
	sessionID := task.SessionID
	if sessionID == "" {
		sessionID = "default"
	}

	// Fetch episodic memories for this session
	// The store allows retrieving chronological memories
	// Using the recall method with session filter
	results, err := w.manager.Recall(ctx, brain.RecallRequest{
		SessionID: sessionID,
		Query:     "architecture invariant convention decision",
		Limit:     25,
		MinScore:  0.0,
	})
	if err != nil {
		return fmt.Errorf("failed to recall memories for reflection: %w", err)
	}

	var nodes []*brain.MemoryNode
	for _, r := range results {
		nodes = append(nodes, r.Node)
	}

	// Generate autonomous reflection
	reflection, err := w.router.Reflect(ctx, sessionID, nodes)
	if err != nil {
		return fmt.Errorf("reflection engine failed: %w", err)
	}

	category := "reflection"
	if task.Type == queue.TaskSummarizeSession {
		category = "summary"
	}

	// Persist the synthesized reflection
	_, err = w.manager.Remember(ctx, brain.RememberRequest{
		SessionID:  sessionID,
		Category:   category,
		Content:    reflection,
		Provenance: brain.ProvenanceLocalWorkspace,
		Metadata: map[string]string{
			"task_id":     task.ID,
			"synthesized": "true",
		},
	})
	return err
}

func (w *CognitiveWorker) handleExtractDecisions(ctx context.Context, task *queue.TaskEnvelope) error {
	sessionID := task.SessionID
	if sessionID == "" {
		sessionID = "default"
	}

	results, err := w.manager.Recall(ctx, brain.RecallRequest{
		SessionID: sessionID,
		Query:     "decision decided ADR choose implement architectural",
		Limit:     25,
		MinScore:  0.0,
	})
	if err != nil {
		return fmt.Errorf("failed to recall memories for decision extraction: %w", err)
	}

	var nodes []*brain.MemoryNode
	for _, r := range results {
		nodes = append(nodes, r.Node)
	}

	if len(nodes) == 0 {
		return nil
	}

	distilled, err := w.router.DistillDecisions(ctx, sessionID, nodes)
	if err != nil {
		return fmt.Errorf("failed to distill decisions: %w", err)
	}

	_, err = w.manager.Remember(ctx, brain.RememberRequest{
		SessionID:  sessionID,
		Category:   "decision",
		Content:    distilled,
		Provenance: brain.ProvenanceLocalWorkspace,
		Metadata: map[string]string{
			"task_id":     task.ID,
			"synthesized": "true",
		},
	})
	return err
}

func (w *CognitiveWorker) handleDefrag(ctx context.Context) error {
	// 1. Purge expired memories across vaults
	_, _ = w.manager.PurgeExpired(ctx)

	// 2. Perform passive WAL checkpoint and vacuum
	_ = w.manager.Vacuum(ctx)

	// 3. Update scratchpad with defrag timestamp
	sp := w.manager.Scratchpad()
	if sp != nil {
		_ = sp.Set(ctx, "last_defrag_time", time.Now().Format(time.RFC3339), 0)
	}

	return nil
}

func (w *CognitiveWorker) handleIndexGitTree(ctx context.Context, task *queue.TaskEnvelope) error {
	dir := "."
	if task.Payload != nil {
		if d, ok := task.Payload["dir"].(string); ok && d != "" {
			dir = d
		}
	}
	_, err := indexer.IndexDirectory(ctx, w.manager, dir, indexer.IndexOptions{})
	return err
}

// Metrics returns current worker telemetry.
func (w *CognitiveWorker) Metrics() WorkerMetrics {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return WorkerMetrics{
		TasksProcessed: atomic.LoadUint64(&w.metrics.TasksProcessed),
		TasksFailed:    atomic.LoadUint64(&w.metrics.TasksFailed),
		LastTaskTime:   w.metrics.LastTaskTime,
	}
}

// Stop shuts down the worker and waits for active task processing to complete.
func (w *CognitiveWorker) Stop() {
	if w.cancelFunc != nil {
		w.cancelFunc()
	}
	w.wg.Wait()
}
