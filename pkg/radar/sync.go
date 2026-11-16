package radar

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/bonjoski/coppermind/pkg/brain"
)

// SyncResult captures the metrics and outcomes of a radar sync pass.
type SyncResult struct {
	TotalFeeds     int      `json:"total_feeds"`
	TotalItems     int      `json:"total_items"`
	IngestedCount  int      `json:"ingested_count"`
	SkippedCount   int      `json:"skipped_count"`
	Errors         []string `json:"errors,omitempty"`
	DurationMillis int64    `json:"duration_ms"`
}

// Syncer coordinates out-of-band radar ingestion into the brain manager.
type Syncer struct {
	cfg *RadarConfig
	mgr *brain.Manager
}

// NewSyncer creates a new radar syncer.
func NewSyncer(cfg *RadarConfig, mgr *brain.Manager) *Syncer {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &Syncer{
		cfg: cfg,
		mgr: mgr,
	}
}

// SyncPass executes an asynchronous sync across all active feeds.
func (s *Syncer) SyncPass(ctx context.Context) (*SyncResult, error) {
	if !s.cfg.Settings.Enabled {
		return &SyncResult{
			TotalFeeds: 0,
			Errors:     []string{"radar is disabled by default: set 'settings.enabled: true' in radar.yaml to activate"},
		}, nil
	}

	start := time.Now()
	feeds := s.cfg.ActiveFeeds()

	res := &SyncResult{
		TotalFeeds: len(feeds),
	}

	var mu sync.Mutex

	for _, feed := range feeds {
		adapter, err := GetAdapter(feed.Adapter)
		if err != nil {
			mu.Lock()
			res.Errors = append(res.Errors, fmt.Sprintf("feed %q: %v", feed.ID, err))
			mu.Unlock()
			continue
		}

		items, err := adapter.Fetch(ctx, feed)
		if err != nil {
			mu.Lock()
			res.Errors = append(res.Errors, fmt.Sprintf("feed %q fetch error: %v", feed.ID, err))
			mu.Unlock()
			continue
		}

		maxItems := s.cfg.Settings.MaxFactsPerFeed
		if maxItems <= 0 {
			maxItems = 50
		}
		if len(items) > maxItems {
			items = items[:maxItems]
		}

		mu.Lock()
		res.TotalItems += len(items)
		mu.Unlock()

		for _, it := range items {
			fact, err := DistillItem(it, feed)
			if err != nil {
				mu.Lock()
				res.Errors = append(res.Errors, fmt.Sprintf("distill error %q: %v", it.Title, err))
				mu.Unlock()
				continue
			}

			// Signal-to-Noise Gate: Filter out noise below configured minimum severity threshold
			if s.cfg.Settings.MinSeverity != "" && SeverityRank(fact.Severity) < SeverityRank(s.cfg.Settings.MinSeverity) {
				mu.Lock()
				res.SkippedCount++
				mu.Unlock()
				continue
			}

			if s.mgr != nil {
				req := fact.ToRememberRequest("")
				req.Deduplicate = true
				_, err = s.mgr.Remember(ctx, req)
				if err != nil {
					mu.Lock()
					res.Errors = append(res.Errors, fmt.Sprintf("ingest error %q: %v", it.Title, err))
					mu.Unlock()
					continue
				}
			}

			mu.Lock()
			res.IngestedCount++
			mu.Unlock()
		}
	}

	res.DurationMillis = time.Since(start).Milliseconds()
	return res, nil
}
