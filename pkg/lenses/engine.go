package lenses

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/project"
	"github.com/bonjoski/coppermind/pkg/queue"
	"github.com/bonjoski/coppermind/pkg/router"
)

// Engine orchestrates asynchronous lens subscriptions, pre-filter evaluation, and observation synthesis.
type Engine struct {
	config     *LensesConfig
	broker     queue.Broker
	manager    *brain.Manager
	router     router.ModelRouter
	project    string
	projectMgr *project.Manager

	mu     sync.RWMutex
	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewEngine constructs a new Cognitive Lenses Engine.
func NewEngine(cfg *LensesConfig, broker queue.Broker, mgr *brain.Manager, rtr router.ModelRouter, projectName string, projMgr *project.Manager) *Engine {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if projectName == "" {
		projectName = "default"
	}

	return &Engine{
		config:     cfg,
		broker:     broker,
		manager:    mgr,
		router:     rtr,
		project:    projectName,
		projectMgr: projMgr,
		stopCh:     make(chan struct{}),
	}
}

// Start registers subscriptions on the message broker and wires the brain manager event hook.
func (e *Engine) Start(ctx context.Context) error {
	// 1. Wire brain manager event hook to broadcast canonical memory lifecycle events
	if e.manager != nil && e.broker != nil {
		e.manager.SetEventHook(func(hookCtx context.Context, topic string, node *brain.MemoryNode) {
			// Anti-recursion invariant: Never emit events for derived memory nodes
			if node.Derived {
				return
			}
			task := &queue.TaskEnvelope{
				SessionID: node.SessionID,
				Type:      queue.TaskType(topic),
				Payload: map[string]interface{}{
					"node_id":    node.ID,
					"category":   node.Category,
					"content":    node.Content,
					"provenance": string(node.Provenance),
					"hash":       node.Hash,
					"project":    e.project,
				},
				CreatedAt: time.Now(),
			}
			_ = e.broker.Publish(hookCtx, topic, task)
		})
	}

	// 2. Register lens topic subscriptions
	if e.broker != nil {
		for i := range e.config.Lenses {
			lens := &e.config.Lenses[i]
			for _, topicPattern := range lens.Subscribe {
				lensCopy := *lens
				err := e.broker.Subscribe(ctx, topicPattern, func(taskCtx context.Context, task *queue.TaskEnvelope) error {
					return e.handleTask(taskCtx, &lensCopy, task)
				})
				if err != nil {
					return fmt.Errorf("failed to subscribe lens %q to topic %q: %w", lens.Name, topicPattern, err)
				}
			}
		}
	}

	return nil
}

// Stop cleanly terminates the engine.
func (e *Engine) Stop() {
	select {
	case <-e.stopCh:
		return
	default:
		close(e.stopCh)
	}
	e.wg.Wait()
}

// handleTask processes an incoming task envelope for a specific lens.
func (e *Engine) handleTask(ctx context.Context, lens *LensConfig, task *queue.TaskEnvelope) error {
	e.wg.Add(1)
	defer e.wg.Done()

	// Extract candidate node payload
	var nodeID, content, hash string
	if task.Payload != nil {
		if id, ok := task.Payload["node_id"].(string); ok {
			nodeID = id
		}
		if c, ok := task.Payload["content"].(string); ok {
			content = c
		}
		if h, ok := task.Payload["hash"].(string); ok {
			hash = h
		}
		// Vault isolation check: Drop task if originating from a different project and cross-vault is not set
		if taskProj, ok := task.Payload["project"].(string); ok && taskProj != "" && taskProj != e.project {
			if cross, _ := task.Payload["cross_vault"].(bool); !cross {
				return nil
			}
		}
	}

	// Retrieve full memory node if not in payload
	var candidate *brain.MemoryNode
	if nodeID != "" && e.manager != nil {
		n, err := e.manager.Store().GetByID(ctx, nodeID)
		if err == nil && n != nil {
			candidate = n
			content = n.Content
			hash = n.Hash
		}
	}

	if candidate == nil {
		if content == "" {
			return nil
		}
		candidate = &brain.MemoryNode{
			ID:        nodeID,
			SessionID: task.SessionID,
			Category:  string(task.Type),
			Content:   content,
			Hash:      hash,
			CreatedAt: task.CreatedAt,
		}
	}

	// Anti-recursion invariant: Never evaluate derived records
	if candidate.Derived {
		return nil
	}

	_, err := e.ProcessCandidate(ctx, lens, candidate)
	return err
}

// ProcessCandidate executes the pre-filter, recalls context, invokes the LLM, and persists observations.
func (e *Engine) ProcessCandidate(ctx context.Context, lens *LensConfig, candidate *brain.MemoryNode) ([]*brain.MemoryNode, error) {
	if candidate.Derived {
		return nil, nil
	}

	// 1. Zero-cost Pre-Filter Gate
	if !lens.MatchesPrefilter(candidate.Content) {
		return nil, nil // Silently bypassed with 0 LLM cost
	}

	// 2. Recall Context Memories across configured categories
	var contextMemories []*brain.MemoryNode
	if e.manager != nil && len(lens.RecallCategories) > 0 {
		for _, cat := range lens.RecallCategories {
			recalled, err := e.manager.Recall(ctx, brain.RecallRequest{
				SessionID: candidate.SessionID,
				Category:  cat,
				Query:     candidate.Content,
				Limit:     3,
				MinScore:  0.3,
			})
			if err == nil {
				for _, r := range recalled {
					if !r.Node.Derived && r.Node.ID != candidate.ID {
						contextMemories = append(contextMemories, r.Node)
					}
				}
			}
		}
	}

	// 3. Invoke LiteLLM via Model Router
	modelResp, err := EvaluateCandidate(ctx, lens, candidate, contextMemories, e.router)
	if err != nil {
		return nil, err
	}

	if len(modelResp.Findings) == 0 {
		return nil, nil
	}

	// 4. Single-Writer Persistence with Deduplication
	var savedObservations []*brain.MemoryNode
	for _, finding := range modelResp.Findings {
		dedupHash := ComputeDedupHash(e.project, lens.Name, candidate.Hash, finding.Summary)

		// Check if an unresolved observation with identical dedup hash already exists
		if existing, err := e.manager.GetByDedupHash(ctx, dedupHash); err == nil && existing != nil {
			continue // Idempotent skip: identical unresolved observation already exists
		}

		obsContent := fmt.Sprintf("[%s] %s: %s", strings.ToUpper(finding.Severity), lens.Name, finding.Summary)
		if finding.Evidence != "" {
			obsContent += fmt.Sprintf("\nEvidence: %s", finding.Evidence)
		}

		meta := map[string]string{
			"lens":             lens.Name,
			"severity":         finding.Severity,
			"finding_category": finding.Category,
			"project":          e.project,
		}

		obsNode, err := e.manager.Remember(ctx, brain.RememberRequest{
			SessionID:   candidate.SessionID,
			Category:    "observation",
			Content:     obsContent,
			Provenance:  brain.ProvenanceLocalWorkspace,
			Metadata:    meta,
			Derived:     true,
			SourceLens:  lens.Name,
			ParentIDs:   []string{candidate.ID},
			Severity:    finding.Severity,
			Status:      "open",
			DedupHash:   dedupHash,
			Deduplicate: false,
		})
		if err != nil {
			return savedObservations, fmt.Errorf("failed to persist observation: %w", err)
		}
		savedObservations = append(savedObservations, obsNode)
	}

	return savedObservations, nil
}

// Reflect executes on-demand reflection over memories for specified lenses.
func (e *Engine) Reflect(ctx context.Context, req ReflectRequest) (*ReflectResult, error) {
	result := &ReflectResult{}

	// Determine lenses to run
	var targetLenses []*LensConfig
	if req.Lens == "all" || req.Lens == "" {
		for i := range e.config.Lenses {
			targetLenses = append(targetLenses, &e.config.Lenses[i])
		}
	} else {
		lens, ok := e.config.GetLens(req.Lens)
		if !ok {
			return nil, fmt.Errorf("unknown lens: %q", req.Lens)
		}
		targetLenses = append(targetLenses, lens)
	}

	// Fetch candidates if not provided
	candidates := req.CandidateNodes
	if len(candidates) == 0 && e.manager != nil {
		limit := req.Limit
		if limit <= 0 {
			limit = 100
		}
		falseDerived := false

		// 1. Episodic recall across memories
		episodic, err := e.manager.Store().RecallEpisodic(ctx, req.SessionID, limit)
		if err == nil {
			now := time.Now()
			for _, n := range episodic {
				if n.Derived {
					continue
				}
				if req.Since > 0 && now.Sub(n.CreatedAt) > req.Since {
					continue
				}
				candidates = append(candidates, n)
			}
		}

		// 2. Semantic recall across key architectural and security concepts
		recalled, err := e.manager.Recall(ctx, brain.RecallRequest{
			SessionID: req.SessionID,
			Query:     "architecture security pattern convention decision vulnerability failure invariant",
			Limit:     limit,
			Derived:   &falseDerived,
			MinScore:  0.0,
		})
		if err == nil {
			seen := make(map[string]bool)
			for _, c := range candidates {
				seen[c.ID] = true
			}
			now := time.Now()
			for _, r := range recalled {
				if r.Node.Derived || seen[r.Node.ID] {
					continue
				}
				if req.Since > 0 && now.Sub(r.Node.CreatedAt) > req.Since {
					continue
				}
				candidates = append(candidates, r.Node)
				seen[r.Node.ID] = true
			}
		}
	}

	if len(candidates) == 0 {
		return result, nil
	}

	// Execute evaluation per lens
	for _, lens := range targetLenses {
		for _, cand := range candidates {
			if !lens.MatchesPrefilter(cand.Content) {
				result.SkippedCount++
				continue
			}

			result.EvaluatedCount++
			obsList, err := e.ProcessCandidate(ctx, lens, cand)
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("lens %s on node %s: %v", lens.Name, cand.ID, err))
				continue
			}
			result.Observations = append(result.Observations, obsList...)
		}
	}

	return result, nil
}
