package radar

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/bonjoski/coppermind/pkg/brain"
)

// SyncResult captures the metrics and outcomes of a radar sync pass.
type SyncResult struct {
	TotalFeeds           int      `json:"total_feeds"`
	TotalItems           int      `json:"total_items"`
	IngestedCount        int      `json:"ingested_count"`
	CapsuleIngestedCount int      `json:"capsule_ingested_count"`
	SkippedCount         int      `json:"skipped_count"`
	CapsulesChecked      []string `json:"capsules_checked,omitempty"`
	Errors               []string `json:"errors,omitempty"`
	DurationMillis       int64    `json:"duration_ms"`
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
// When radar is disabled (Settings.Enabled == false), capsules are the ONLY data ingested (offline baseline mode).
// When radar is enabled, capsules are ingested first, followed by live external feed synchronization.
func (s *Syncer) SyncPass(ctx context.Context) (*SyncResult, error) {
	start := time.Now()
	res := &SyncResult{}

	var mu sync.Mutex

	// 1. FIRST INGESTION POINT: Discover and ingest local radar capsule archives.
	// Capsules are offline, immutable, and are the ONLY data ingested if the radar is disabled.
	capsules := FindCapsules(s.cfg)
	res.CapsulesChecked = capsules
	for _, capPath := range capsules {
		count, err := IngestCapsule(ctx, capPath, s.mgr)
		if err != nil {
			mu.Lock()
			res.Errors = append(res.Errors, fmt.Sprintf("capsule %q error: %v", filepath.Base(capPath), err))
			mu.Unlock()
		} else {
			mu.Lock()
			res.CapsuleIngestedCount += count
			res.IngestedCount += count
			mu.Unlock()
		}
	}

	// If radar is disabled, capsules are the ONLY data ingested; skip all live network feeds.
	if !s.cfg.Settings.Enabled {
		res.DurationMillis = time.Since(start).Milliseconds()
		return res, nil
	}

	feeds := s.cfg.ActiveFeeds()
	res.TotalFeeds = len(feeds)

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

			// Signal-to-Noise Gate:
			// Vulnerabilities are gated by MinSeverity (default: "high") to avoid CVE flood.
			// Architectural standards and deprecations are high-signal by definition for systems architects and pass unless ranked below "medium".
			if fact.Category == CategoryVulnerability || fact.Category == CategoryExploitPrimitive {
				if s.cfg.Settings.MinSeverity != "" && SeverityRank(fact.Severity) < SeverityRank(s.cfg.Settings.MinSeverity) {
					mu.Lock()
					res.SkippedCount++
					mu.Unlock()
					continue
				}
			} else {
				if SeverityRank(fact.Severity) < SeverityRank(SeverityMedium) {
					mu.Lock()
					res.SkippedCount++
					mu.Unlock()
					continue
				}
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
