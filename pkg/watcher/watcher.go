package watcher

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/bonjoski/coppermind/pkg/authz"
	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/graph"
	"github.com/bonjoski/coppermind/pkg/scope"
	"github.com/bonjoski/coppermind/pkg/security"
	"github.com/bonjoski/coppermind/pkg/storage"
)

const (
	// DefaultMaxFileBytes caps individual Markdown note size at 512 KiB.
	DefaultMaxFileBytes = 512 * 1024
	// DefaultPollInterval defines the read-only watcher scan cadence.
	DefaultPollInterval = 5 * time.Second
)

var (
	// ErrRootSymlinkRefused rejects symlinked vault roots fail-closed.
	ErrRootSymlinkRefused = errors.New("watcher security violation: symlinked vault root refused fail-closed")

	// Linear RE2 Obsidian [[wikilink]] extractor (handles [[Note]], [[Note#Heading]], [[Note|Alias]]).
	reWikilink = regexp.MustCompile(`\[\[([^\]|#\r\n]{1,120})(?:#[^\]|\r\n]{0,80})?(?:\|[^\]\r\n]{0,80})?\]\]`)
	reSlugBad  = regexp.MustCompile(`[^a-z0-9/_-]+`)
)

// Options controls local read-only Markdown/Obsidian/ADR vault synchronization.
type Options struct {
	Category      string        // Defaults to "note"
	Scope         string        // Optional base canonical hierarchical scope
	ScopeFromDirs bool          // If true, map relative subdirectories into nested child scopes
	Interval      time.Duration // Poll interval for WatchVault (defaults to 5s)
	MaxFileBytes  int64         // Max Markdown file bytes (defaults to 512 KiB)
}

// SyncStats reports the deterministic outcome of a single read-only vault sync pass.
type SyncStats struct {
	VaultName          string        `json:"vault_name"`
	SessionID          string        `json:"session_id"`
	ScannedFiles       int           `json:"scanned_files"`
	IndexedFiles       int           `json:"indexed_files"`
	SkippedUnchanged   int           `json:"skipped_unchanged"`
	PrunedFiles        int           `json:"pruned_files"`
	QuarantinedFiles   int           `json:"quarantined_files"`
	SymlinksSkipped    int           `json:"symlinks_skipped"`
	WikilinksExtracted int           `json:"wikilinks_extracted"`
	Duration           time.Duration `json:"duration"`
}

// NoteFrontmatter holds deterministic metadata extracted from leading YAML frontmatter.
type NoteFrontmatter struct {
	Title   string
	Status  string
	Tags    []string
	Aliases []string
}

// SyncVaultOnce performs a single read-only, hash-incremental synchronization of a local
// Obsidian, Markdown, or ADR directory into Coppermind. Never modifies files inside rootDir.
func SyncVaultOnce(ctx context.Context, mgr *brain.Manager, rootDir string, opts Options) (*SyncStats, error) {
	start := time.Now()
	if mgr == nil {
		return nil, fmt.Errorf("brain manager is required")
	}
	idxStore, ok := mgr.Store().(storage.IndexedFileStore)
	if !ok {
		return nil, fmt.Errorf("vault watcher requires a backend supporting incremental file manifests (SQLite or PostgreSQL)")
	}
	graphStore, _ := mgr.Store().(storage.GraphStore)

	absRoot, err := filepath.Abs(strings.TrimSpace(rootDir))
	if err != nil {
		return nil, fmt.Errorf("invalid vault root: %w", err)
	}
	linfo, err := os.Lstat(absRoot)
	if err != nil {
		return nil, fmt.Errorf("cannot access vault root %q: %w", absRoot, err)
	}
	if linfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: %s", ErrRootSymlinkRefused, absRoot)
	}
	if !linfo.IsDir() {
		return nil, fmt.Errorf("vault root %q is not a directory", absRoot)
	}

	// Syscall-confined directory root prevents TOCTOU symlink escapes outside absRoot.
	rootFS, err := os.OpenRoot(absRoot)
	if err != nil {
		return nil, fmt.Errorf("failed confining vault root: %w", err)
	}
	defer rootFS.Close()

	baseScope, err := scope.Normalize(opts.Scope)
	if err != nil {
		return nil, err
	}

	category := strings.TrimSpace(opts.Category)
	if category == "" {
		category = "note"
	}
	maxBytes := opts.MaxFileBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxFileBytes
	}

	vaultName := filepath.Base(absRoot)
	sessionID := "vault:" + vaultName
	manifestKey := "vault:" + absRoot

	existing, err := idxStore.ListIndexedFiles(ctx, manifestKey)
	if err != nil {
		return nil, fmt.Errorf("failed loading vault manifest: %w", err)
	}

	stats := &SyncStats{
		VaultName: vaultName,
		SessionID: sessionID,
	}
	seenRel := make(map[string]bool)

	walkErr := filepath.WalkDir(absRoot, func(path string, d fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			return nil
		}
		if path == absRoot {
			return nil
		}

		name := d.Name()
		// Skip hidden metadata directories (.git, .obsidian, .trash) and node_modules
		if d.IsDir() {
			if strings.HasPrefix(name, ".") || name == "node_modules" {
				return filepath.SkipDir
			}
		}

		// Explicit Lstat check refuses symlinked directories and files fail-closed
		fi, lErr := os.Lstat(path)
		if lErr != nil {
			return nil
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			stats.SymlinksSkipped++
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if fi.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(name))
		if ext != ".md" && ext != ".markdown" {
			return nil
		}
		if fi.Size() > maxBytes {
			return nil
		}

		rel, rErr := filepath.Rel(absRoot, path)
		if rErr != nil {
			return nil
		}
		relSlash := filepath.ToSlash(rel)
		seenRel[relSlash] = true
		stats.ScannedFiles++

		// Open strictly via os.Root to prevent TOCTOU symlink swaps
		f, oErr := rootFS.Open(rel)
		if oErr != nil {
			stats.SymlinksSkipped++
			return nil
		}
		rawBytes, readErr := io.ReadAll(io.LimitReader(f, maxBytes+1))
		_ = f.Close()
		if readErr != nil || int64(len(rawBytes)) > maxBytes {
			return nil
		}

		sum := sha256.Sum256(rawBytes)
		fileSHA := hex.EncodeToString(sum[:])
		if prev, ok := existing[relSlash]; ok && prev.ContentSHA256 == fileSHA {
			stats.SkippedUnchanged++
			return nil
		}

		// File is new or modified: remove stale chunks first
		if prev, ok := existing[relSlash]; ok && len(prev.ChunkIDs) > 0 {
			if delErr := idxStore.DeleteIndexedChunks(ctx, prev.ChunkIDs); delErr != nil {
				return fmt.Errorf("failed clearing stale chunks for %s: %w", relSlash, delErr)
			}
		}

		fm, body := ParseFrontmatter(string(rawBytes))
		cleanBody := strings.TrimSpace(body)
		if cleanBody == "" {
			return nil
		}

		// Security gate: sanitize secrets & quarantine critical cognitive prompt injections
		secRes, secErr := security.SanitizeMemory(cleanBody)
		if secErr != nil {
			stats.QuarantinedFiles++
			return nil
		}
		if threat, tErr := security.InspectCognitiveThreats(secRes.SanitizedText); tErr == nil && threat != nil && threat.IsCritical {
			stats.QuarantinedFiles++
			return nil
		}

		title := fm.Title
		if title == "" {
			title = strings.TrimSuffix(filepath.Base(relSlash), filepath.Ext(relSlash))
		}

		// Format indexed note content with structured header for strong BM25 + semantic recall
		var contentBuf strings.Builder
		fmt.Fprintf(&contentBuf, "# %s (%s)\n", title, relSlash)
		if len(fm.Tags) > 0 {
			fmt.Fprintf(&contentBuf, "Tags: %s\n", strings.Join(fm.Tags, ", "))
		}
		if fm.Status != "" {
			fmt.Fprintf(&contentBuf, "Status: %s\n", fm.Status)
		}
		contentBuf.WriteString("\n")
		contentBuf.WriteString(secRes.SanitizedText)

		tier := authz.TierName3Episodic
		upperRel := strings.ToUpper(relSlash)
		if strings.Contains(upperRel, "ADR") || strings.Contains(upperRel, "RFC") {
			tier = authz.TierName1Architecture
		}

		meta := map[string]string{
			"vault_name":   vaultName,
			"path":         relSlash,
			"note_title":   title,
			"content_type": "obsidian_note",
		}
		if len(fm.Tags) > 0 {
			meta["note_tags"] = strings.Join(fm.Tags, ",")
		}
		if len(fm.Aliases) > 0 {
			meta["note_aliases"] = strings.Join(fm.Aliases, ",")
		}

		noteScope := baseScope
		if opts.ScopeFromDirs {
			if derivedScope, dErr := scope.FromRelativeDir(baseScope, filepath.ToSlash(filepath.Dir(rel))); dErr == nil {
				noteScope = derivedScope
			}
		}

		stored, storeErr := mgr.Remember(ctx, brain.RememberRequest{
			SessionID:     sessionID,
			Category:      category,
			Scope:         noteScope,
			Content:       contentBuf.String(),
			Provenance:    brain.ProvenanceLocalWorkspace,
			AuthorityTier: tier,
			Metadata:      meta,
		})
		if storeErr != nil {
			stats.QuarantinedFiles++
			return nil
		}

		// Extract Obsidian [[wikilinks]] -> graph edges, strictly honoring global MaxEdgesPerNode (32)
		if graphStore != nil {
			existingEdges, _ := graphStore.GetEdgesForNode(ctx, stored.ID)
			remaining := graph.MaxEdgesPerNode - len(existingEdges)
			if remaining > 0 {
				edges := ExtractWikilinkEdges(stored.ID, relSlash, title, secRes.SanitizedText)
				if len(edges) > remaining {
					edges = edges[:remaining]
				}
				if len(edges) > 0 {
					if err := graphStore.StoreEdges(ctx, edges); err == nil {
						stats.WikilinksExtracted += len(edges)
					}
				}
			}
		}

		if err := idxStore.UpsertIndexedFile(ctx, storage.IndexedFileRecord{
			RepoRoot:      manifestKey,
			RelPath:       relSlash,
			ContentSHA256: fileSHA,
			ChunkIDs:      []string{stored.ID},
			IndexedAt:     time.Now().UTC(),
		}); err != nil {
			return err
		}
		stats.IndexedFiles++
		return nil
	})
	if walkErr != nil {
		return stats, walkErr
	}

	// Prune deleted notes from the manifest and memory store without touching other sessions
	for relPath, rec := range existing {
		if !seenRel[relPath] {
			if err := idxStore.PruneIndexedFile(ctx, manifestKey, relPath, rec.ChunkIDs); err == nil {
				stats.PrunedFiles++
			}
		}
	}

	stats.Duration = time.Since(start)
	return stats, nil
}

// WatchVault runs an initial read-only sync followed by periodic hash-incremental scans
// until ctx is cancelled.
func WatchVault(ctx context.Context, mgr *brain.Manager, rootDir string, opts Options, onSync func(*SyncStats, error)) error {
	interval := opts.Interval
	if interval <= 0 {
		interval = DefaultPollInterval
	}

	stats, err := SyncVaultOnce(ctx, mgr, rootDir, opts)
	if onSync != nil {
		onSync(stats, err)
	}
	if err != nil {
		return err
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			s, sErr := SyncVaultOnce(ctx, mgr, rootDir, opts)
			if onSync != nil {
				onSync(s, sErr)
			}
		}
	}
}

// ParseFrontmatter deterministically extracts simple YAML frontmatter (title, status, tags, aliases)
// without external YAML parsers or anchor-expansion vulnerabilities.
func ParseFrontmatter(raw string) (NoteFrontmatter, string) {
	var fm NoteFrontmatter
	norm := strings.ReplaceAll(raw, "\r\n", "\n")
	if !strings.HasPrefix(norm, "---\n") {
		return fm, raw
	}
	rest := norm[4:]
	endIdx := strings.Index(rest, "\n---\n")
	bodyStart := endIdx + 5
	if endIdx < 0 {
		if strings.HasSuffix(rest, "\n---") {
			endIdx = len(rest) - 4
			bodyStart = len(rest)
		} else {
			return fm, raw
		}
	}
	header := rest[:endIdx]
	body := rest[bodyStart:]

	currentList := ""
	for _, line := range strings.Split(header, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "- ") && currentList != "" {
			val := strings.Trim(strings.TrimSpace(strings.TrimPrefix(trimmed, "- ")), `"'`)
			if val != "" {
				if currentList == "tags" && len(fm.Tags) < 32 {
					fm.Tags = append(fm.Tags, val)
				} else if currentList == "aliases" && len(fm.Aliases) < 16 {
					fm.Aliases = append(fm.Aliases, val)
				}
			}
			continue
		}
		currentList = ""
		colon := strings.IndexByte(trimmed, ':')
		if colon <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(trimmed[:colon]))
		val := strings.TrimSpace(trimmed[colon+1:])
		switch key {
		case "title":
			fm.Title = strings.Trim(val, `"'`)
		case "status":
			fm.Status = strings.Trim(val, `"'`)
		case "tags":
			if val == "" {
				currentList = "tags"
			} else {
				fm.Tags = append(fm.Tags, parseInlineList(val, 32)...)
			}
		case "aliases":
			if val == "" {
				currentList = "aliases"
			} else {
				fm.Aliases = append(fm.Aliases, parseInlineList(val, 16)...)
			}
		}
	}
	return fm, body
}

func parseInlineList(raw string, maxItems int) []string {
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	var out []string
	for _, part := range strings.Split(s, ",") {
		p := strings.Trim(strings.TrimSpace(part), `"'`)
		if p != "" {
			out = append(out, p)
			if len(out) >= maxItems {
				break
			}
		}
	}
	return out
}

// NormalizeNoteSlug canonicalizes an Obsidian note name or relative path into a graph entity slug.
func NormalizeNoteSlug(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	s = strings.TrimSuffix(s, ".md")
	s = strings.TrimSuffix(s, ".markdown")
	s = strings.ReplaceAll(s, " ", "-")
	s = reSlugBad.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-/")
	if len(s) > 100 {
		s = s[:100]
	}
	return s
}

// ExtractWikilinkEdges emits canonical "note:<slug>" graph edges for a note's own identity
// and all [[wikilink]] references, strictly capped at graph.MaxEdgesPerNode (32).
func ExtractWikilinkEdges(nodeID, relPath, title, content string) []graph.Edge {
	if nodeID == "" {
		return nil
	}
	seen := make(map[string]struct{}, graph.MaxEdgesPerNode)
	var edges []graph.Edge
	now := time.Now().UTC()

	add := func(slug string, weight float32) {
		if slug == "" || len(edges) >= graph.MaxEdgesPerNode {
			return
		}
		entity := "note:" + slug
		if _, dup := seen[entity]; dup {
			return
		}
		seen[entity] = struct{}{}
		sum := sha256.Sum256([]byte(nodeID + ":" + string(graph.RelRelatedTo) + ":" + entity))
		edges = append(edges, graph.Edge{
			ID:           "edge_" + hex.EncodeToString(sum[:8]),
			SourceID:     nodeID,
			TargetEntity: entity,
			Relation:     graph.RelRelatedTo,
			Weight:       weight,
			CreatedAt:    now,
		})
	}

	// Self-entity edges so peers linking via [[filename]] or [[title]] connect via 1-hop graph expansion
	add(NormalizeNoteSlug(filepath.Base(relPath)), 1.0)
	if title != "" {
		add(NormalizeNoteSlug(title), 0.95)
	}

	// Bound scanned content to prevent pathological inputs
	scan := content
	if len(scan) > 65536 {
		scan = scan[:65536]
	}
	matches := reWikilink.FindAllStringSubmatch(scan, graph.MaxEdgesPerNode*4)
	for _, m := range matches {
		if len(edges) >= graph.MaxEdgesPerNode {
			break
		}
		if len(m) >= 2 {
			add(NormalizeNoteSlug(m[1]), 0.85)
		}
	}
	return edges
}
