package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/graph"
)

func insertEdgesTx(tx *sql.Tx, node *brain.MemoryNode) error {
	edges := graph.ExtractEdges(node)
	if len(edges) == 0 {
		return nil
	}
	_, _ = tx.Exec("DELETE FROM memory_edges WHERE source_id = ?", node.ID)
	stmt, err := tx.Prepare(`
		INSERT INTO memory_edges (id, source_id, target_id, target_entity, relation, weight, derived, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO NOTHING
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, e := range edges {
		derivedInt := 0
		if e.Derived {
			derivedInt = 1
		}
		if _, err := stmt.Exec(e.ID, e.SourceID, e.TargetID, e.TargetEntity, string(e.Relation), e.Weight, derivedInt, e.CreatedAt.UnixNano()); err != nil {
			return err
		}
	}
	return nil
}

// StoreEdges persists explicit knowledge graph edges via the single-writer ring.
func (s *SQLiteStore) StoreEdges(ctx context.Context, edges []graph.Edge) error {
	if len(edges) == 0 {
		return nil
	}
	return s.RunWriteTx(ctx, func(tx *sql.Tx) error {
		stmt, err := tx.Prepare(`
			INSERT INTO memory_edges (id, source_id, target_id, target_entity, relation, weight, derived, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(id) DO NOTHING
		`)
		if err != nil {
			return err
		}
		defer stmt.Close()
		for _, e := range edges {
			if !graph.IsValidRelation(e.Relation) {
				return fmt.Errorf("invalid graph relation %q", e.Relation)
			}
			derivedInt := 0
			if e.Derived {
				derivedInt = 1
			}
			ts := e.CreatedAt
			if ts.IsZero() {
				ts = time.Now()
			}
			if _, err := stmt.Exec(e.ID, e.SourceID, e.TargetID, e.TargetEntity, string(e.Relation), e.Weight, derivedInt, ts.UnixNano()); err != nil {
				return err
			}
		}
		return nil
	})
}

// GetEdgesForNode returns all outbound and inbound edges connected to nodeID.
func (s *SQLiteStore) GetEdgesForNode(ctx context.Context, nodeID string) ([]graph.Edge, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, source_id, target_id, target_entity, relation, weight, derived, created_at
		FROM memory_edges
		WHERE source_id = ? OR target_id = ?
		ORDER BY weight DESC, created_at DESC
		LIMIT 100
	`, nodeID, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []graph.Edge
	for rows.Next() {
		var e graph.Edge
		var rel string
		var derivedInt int
		var createdNano int64
		if err := rows.Scan(&e.ID, &e.SourceID, &e.TargetID, &e.TargetEntity, &rel, &e.Weight, &derivedInt, &createdNano); err != nil {
			return nil, err
		}
		e.Relation = graph.RelationType(rel)
		e.Derived = derivedInt == 1
		e.CreatedAt = time.Unix(0, createdNano)
		out = append(out, e)
	}
	return out, rows.Err()
}

// GetNodesByEntity returns active memory nodes linked to a canonical graph entity (e.g. "file:pkg/mcp/server.go").
func (s *SQLiteStore) GetNodesByEntity(ctx context.Context, entity string, limit int) ([]*brain.MemoryNode, error) {
	if limit <= 0 || limit > graph.MaxExpandedNodes {
		limit = 20
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT m.`+strings.ReplaceAll(sqliteMemoryColumns, ", ", ", m.")+`
		FROM memory_nodes m
		JOIN memory_edges e ON e.source_id = m.id
		WHERE e.target_entity = ?
		  AND (m.lifecycle_status = 'ACTIVE' OR m.lifecycle_status = '' OR m.lifecycle_status IS NULL)
		ORDER BY m.created_at DESC
		LIMIT ?
	`, entity, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*brain.MemoryNode
	nowNano := time.Now().UnixNano()
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		if n.ExpiresAt != nil && n.ExpiresAt.UnixNano() < nowNano {
			continue
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// ImpactForFile returns active invariants, decisions, observations, and chunks linked to relPath.
func (s *SQLiteStore) ImpactForFile(ctx context.Context, relPath string, limit int) ([]*brain.MemoryNode, error) {
	ent := graph.NormalizeFileEntity(relPath)
	if ent == "" {
		return nil, fmt.Errorf("invalid relative file path %q", relPath)
	}
	return s.GetNodesByEntity(ctx, ent, limit)
}

// ExpandGraphNeighbors performs bounded multi-hop BFS (hard-clamped <=2 hops, <=50 nodes)
// across direct node edges and shared entity edges while strictly enforcing filter & trust invariants.
func (s *SQLiteStore) ExpandGraphNeighbors(ctx context.Context, seedIDs []string, maxHops int, filter brain.MemoryFilter) ([]*brain.SearchResult, error) {
	if len(seedIDs) == 0 || maxHops <= 0 {
		return nil, nil
	}
	if maxHops > graph.MaxGraphHops {
		maxHops = graph.MaxGraphHops
	}

	visited := make(map[string]bool, len(seedIDs)+graph.MaxExpandedNodes)
	taintedPath := make(map[string]bool, len(seedIDs)+graph.MaxExpandedNodes)
	frontier := make([]string, 0, len(seedIDs))
	for _, sid := range seedIDs {
		if sid != "" && !visited[sid] {
			visited[sid] = true
			frontier = append(frontier, sid)
			if sNode, _ := s.getNodeByID(ctx, sid); sNode != nil && sNode.Provenance == brain.ProvenanceUntrustedWeb {
				taintedPath[sid] = true
			}
		}
	}

	linkReasons := make(map[string][]string)
	expandedIDs := make([]string, 0, graph.MaxExpandedNodes)

	for hop := 1; hop <= maxHops && len(frontier) > 0 && len(expandedIDs) < graph.MaxExpandedNodes; hop++ {
		nextFrontier := make([]string, 0, 16)
		for _, curID := range frontier {
			if len(expandedIDs) >= graph.MaxExpandedNodes {
				break
			}
			edges, err := s.GetEdgesForNode(ctx, curID)
			if err != nil {
				continue
			}

			// Propagate untrusted origin taint monotonically across all hops so untrusted seeds
			// can NEVER transitively pull TIER_0_SOVEREIGN nodes on hop 1 or hop 2.
			curUntrusted := taintedPath[curID]
			if !curUntrusted {
				if curNode, _ := s.getNodeByID(ctx, curID); curNode != nil && curNode.Provenance == brain.ProvenanceUntrustedWeb {
					curUntrusted = true
					taintedPath[curID] = true
				}
			}

			for _, e := range edges {
				if len(expandedIDs) >= graph.MaxExpandedNodes {
					break
				}
				// 1. Direct node-to-node edge
				peerID := ""
				if e.SourceID == curID && e.TargetID != "" {
					peerID = e.TargetID
				} else if e.TargetID == curID && e.SourceID != "" {
					peerID = e.SourceID
				}
				if peerID != "" && !visited[peerID] {
					if curUntrusted {
						if pNode, _ := s.getNodeByID(ctx, peerID); pNode != nil && pNode.AuthorityTier == "TIER_0_SOVEREIGN" {
							continue
						}
						taintedPath[peerID] = true
					}
					visited[peerID] = true
					expandedIDs = append(expandedIDs, peerID)
					nextFrontier = append(nextFrontier, peerID)
					linkReasons[peerID] = append(linkReasons[peerID], fmt.Sprintf("%s:%s", e.Relation, curID))
				}

				// 2. Shared high-signal entity edge (files, symbols, RFCs, advisories)
				if e.TargetEntity != "" && !strings.HasPrefix(e.TargetEntity, "repo:") {
					peers, err := s.findPeerNodeIDsByEntity(ctx, e.TargetEntity, 12)
					if err != nil {
						continue
					}
					for _, pid := range peers {
						if len(expandedIDs) >= graph.MaxExpandedNodes {
							break
						}
						if visited[pid] {
							continue
						}
						if curUntrusted {
							if pNode, _ := s.getNodeByID(ctx, pid); pNode != nil && pNode.AuthorityTier == "TIER_0_SOVEREIGN" {
								continue
							}
							taintedPath[pid] = true
						}
						visited[pid] = true
						expandedIDs = append(expandedIDs, pid)
						nextFrontier = append(nextFrontier, pid)
						linkReasons[pid] = append(linkReasons[pid], e.TargetEntity)
					}
				}
			}
		}
		frontier = nextFrontier
	}

	nowNano := time.Now().UnixNano()
	var results []*brain.SearchResult
	for _, id := range expandedIDs {
		node, err := s.getNodeByID(ctx, id)
		if err != nil || node == nil {
			continue
		}
		if !entryMatchesFilter(nodeToSlabEntry(node), filter, nowNano) {
			continue
		}
		// Security invariant: never surface tainted web nodes via graph expansion unless explicitly requested
		if filter.Provenance == "" && node.Provenance == brain.ProvenanceUntrustedWeb {
			continue
		}
		results = append(results, &brain.SearchResult{
			Node:       node,
			Score:      0.55,
			GraphLinks: linkReasons[id],
		})
	}
	return results, nil
}

func (s *SQLiteStore) findPeerNodeIDsByEntity(ctx context.Context, entity string, limit int) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT source_id FROM memory_edges
		WHERE target_entity = ?
		ORDER BY created_at DESC
		LIMIT ?
	`, entity, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil {
			ids = append(ids, id)
		}
	}
	return ids, rows.Err()
}

// GetGraphSubgraph returns bounded nodes and edges for local Brain Explorer visualization.
func (s *SQLiteStore) GetGraphSubgraph(ctx context.Context, centerID string, maxNodes int, maxEdges int) ([]*brain.MemoryNode, []graph.Edge, error) {
	if maxNodes <= 0 || maxNodes > 100 {
		maxNodes = 100
	}
	if maxEdges <= 0 || maxEdges > 250 {
		maxEdges = 250
	}

	var nodes []*brain.MemoryNode
	nodeSet := make(map[string]bool)

	if centerID != "" {
		if c, err := s.getNodeByID(ctx, centerID); err == nil && c != nil {
			nodes = append(nodes, c)
			nodeSet[c.ID] = true
		}
		neighbors, _ := s.ExpandGraphNeighbors(ctx, []string{centerID}, 2, brain.MemoryFilter{Limit: maxNodes - 1})
		for _, n := range neighbors {
			if len(nodes) >= maxNodes {
				break
			}
			if n.Node != nil && !nodeSet[n.Node.ID] {
				nodes = append(nodes, n.Node)
				nodeSet[n.Node.ID] = true
			}
		}
	} else {
		rows, err := s.db.QueryContext(ctx, `
			SELECT `+sqliteMemoryColumns+`
			FROM memory_nodes
			WHERE lifecycle_status = 'ACTIVE' OR lifecycle_status = '' OR lifecycle_status IS NULL
			ORDER BY created_at DESC
			LIMIT ?
		`, maxNodes)
		if err != nil {
			return nil, nil, err
		}
		for rows.Next() {
			n, err := scanNode(rows)
			if err == nil && n != nil {
				nodes = append(nodes, n)
				nodeSet[n.ID] = true
			}
		}
		rows.Close()
	}

	var edges []graph.Edge
	edgeSeen := make(map[string]bool)
	for _, n := range nodes {
		if len(edges) >= maxEdges {
			break
		}
		nEdges, err := s.GetEdgesForNode(ctx, n.ID)
		if err != nil {
			continue
		}
		for _, e := range nEdges {
			if len(edges) >= maxEdges {
				break
			}
			if edgeSeen[e.ID] {
				continue
			}
			edgeSeen[e.ID] = true
			edges = append(edges, e)
		}
	}
	return nodes, edges, nil
}
