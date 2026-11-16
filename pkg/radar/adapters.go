package radar

import (
	"context"
	"fmt"
	"sync"
)

var (
	registryMu sync.RWMutex
	registry   = make(map[string]FeedAdapter)
)

// Register registers a feed adapter implementation by type name.
func Register(adapter FeedAdapter) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[adapter.Type()] = adapter
}

// GetAdapter returns the feed adapter for the given type name.
func GetAdapter(typeName string) (FeedAdapter, error) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	adapter, ok := registry[typeName]
	if !ok {
		return nil, fmt.Errorf("unknown feed adapter type: %q", typeName)
	}
	return adapter, nil
}

// MemoryAdapter provides in-memory static items for testing, spikes, and offline seeds.
type MemoryAdapter struct {
	Items map[string][]RawItem
	mu    sync.RWMutex
}

// NewMemoryAdapter creates a new memory adapter.
func NewMemoryAdapter() *MemoryAdapter {
	return &MemoryAdapter{
		Items: make(map[string][]RawItem),
	}
}

func (m *MemoryAdapter) Type() string {
	return "static"
}

func (m *MemoryAdapter) SetItems(feedID string, items []RawItem) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Items[feedID] = items
}

func (m *MemoryAdapter) Fetch(ctx context.Context, config FeedConfig) ([]RawItem, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	items, ok := m.Items[config.ID]
	if !ok {
		return []RawItem{}, nil
	}
	return items, nil
}

func init() {
	Register(NewMemoryAdapter())
}
