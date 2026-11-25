package indexer

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/gitscope"
	"github.com/bonjoski/coppermind/pkg/scope"
	"github.com/bonjoski/coppermind/pkg/security"
	"github.com/bonjoski/coppermind/pkg/storage/sqlite"
)

// IndexOptions configures codebase traversal and AST/structural incremental chunking.
type IndexOptions struct {
	MaxFileSize     int64        // Maximum file size in bytes to index (default: 512KB)
	MaxChunks       int          // Maximum total chunks to create per run (default: 10000)
	SkipDirs        []string     // Extra directory names to skip
	ChunkLines      int          // Target lines per structural fallback chunk (default: 50)
	Overlap         int          // Overlap lines between fallback chunks (default: 5)
	Category        string       // Target category (default: "code")
	Scope           string       // Optional canonical hierarchical scope (e.g. "platform/payments")
	ScopeFromConfig bool         // If true, resolve per-file scopes from repo-confined .coppermind.yaml
	FullRebuild     bool         // If true, ignore SHA-256 cache and re-index all candidate files
	OnProgress      ProgressFunc // Optional callback for real-time indexing progress events
}

// IndexStats reports the outcome of a codebase indexing run.
type IndexStats struct {
	FilesScanned   int           `json:"files_scanned"`
	FilesIndexed   int           `json:"files_indexed"`
	FilesUnchanged int           `json:"files_unchanged"`
	FilesSkipped   int           `json:"files_skipped"`
	FilesPruned    int           `json:"files_pruned"`
	ChunksStored   int           `json:"chunks_stored"`
	ChunksPruned   int           `json:"chunks_pruned"`
	Redactions     int           `json:"redactions"`
	Duration       time.Duration `json:"duration"`
}

var (
	repoLocksMu sync.Mutex
	repoLocks   = make(map[string]*sync.Mutex)
)

func lockRepoIndex(absRoot string) func() {
	repoLocksMu.Lock()
	mu, ok := repoLocks[absRoot]
	if !ok {
		mu = &sync.Mutex{}
		repoLocks[absRoot] = mu
	}
	repoLocksMu.Unlock()
	mu.Lock()
	return mu.Unlock
}

var defaultSkippedDirs = map[string]bool{
	".git":         true,
	".github":      false, // allow indexing workflows
	"node_modules": true,
	"vendor":       true,
	"bin":          true,
	"obj":          true,
	"target":       true,
	"dist":         true,
	"build":        true,
	".venv":        true,
	"venv":         true,
	"__pycache__":  true,
	".idea":        true,
	".vscode":      true,
	".coppermind":  true,
}

var sensitiveFileNames = map[string]bool{
	".env":                 true,
	".env.local":           true,
	".env.production":      true,
	"id_rsa":               true,
	"id_ed25519":           true,
	"id_ecdsa":             true,
	"credentials":          true,
	"credentials.json":     true,
	"service-account.json": true,
}

var supportedExtensions = map[string]bool{
	".go":   true,
	".rs":   true,
	".py":   true,
	".ts":   true,
	".js":   true,
	".tsx":  true,
	".jsx":  true,
	".c":    true,
	".cpp":  true,
	".h":    true,
	".hpp":  true,
	".md":   true,
	".yaml": true,
	".yml":  true,
	".toml": true,
	".json": true,
	".sql":  true,
	".sh":   true,
	".bash": true,
	".zsh":  true,
}

type candidateFile struct {
	path    string
	relPath string
	ext     string
}

type incrementalIndexStore interface {
	ListIndexedFiles(ctx context.Context, repoRoot string) (map[string]sqlite.IndexedFileRecord, error)
	UpsertIndexedFile(ctx context.Context, rec sqlite.IndexedFileRecord) error
	DeleteIndexedChunks(ctx context.Context, chunkIDs []string) error
	PruneIndexedFile(ctx context.Context, repoRoot, relPath string, chunkIDs []string) error
}

// IndexDirectory scans a directory tree with os.OpenRoot symlink confinement, performs
// AST/Markdown/structural chunking, skips unchanged files via SHA-256, swaps stale chunks on
// modification, and prunes deleted files — isolated under session_id="index:<repo>" to preserve
// episodic Merkle chains.
func IndexDirectory(ctx context.Context, mgr *brain.Manager, rootDir string, opts IndexOptions) (*IndexStats, error) {
	start := time.Now()
	stats := &IndexStats{}

	absRoot, err := filepath.Abs(rootDir)
	if err != nil {
		return nil, fmt.Errorf("invalid root directory %s: %w", rootDir, err)
	}

	fiRoot, err := os.Lstat(absRoot)
	if err != nil {
		return nil, fmt.Errorf("cannot access root directory %s: %w", absRoot, err)
	}
	if fiRoot.Mode()&os.ModeSymlink != 0 {
		// Resolve canonical root if caller passed a symlinked tmpdir (e.g. macOS /var -> /private/var),
		// then confine all file reads inside that resolved root via os.OpenRoot.
		resolved, rErr := filepath.EvalSymlinks(absRoot)
		if rErr != nil {
			return nil, fmt.Errorf("failed resolving root directory %s: %w", absRoot, rErr)
		}
		absRoot = resolved
		fiRoot, err = os.Stat(absRoot)
		if err != nil {
			return nil, err
		}
	}
	if !fiRoot.IsDir() {
		return nil, fmt.Errorf("path is not a directory: %s", absRoot)
	}

	unlock := lockRepoIndex(absRoot)
	defer unlock()

	rootFS, err := os.OpenRoot(absRoot)
	if err != nil {
		return nil, fmt.Errorf("failed opening confined root %s: %w", absRoot, err)
	}
	defer rootFS.Close()

	if opts.MaxFileSize <= 0 {
		opts.MaxFileSize = 512 * 1024 // 512KB
	}
	if opts.MaxChunks <= 0 {
		opts.MaxChunks = 10000
	}
	if opts.ChunkLines <= 0 {
		opts.ChunkLines = 50
	}
	if opts.Overlap < 0 {
		opts.Overlap = 5
	}
	if opts.Category == "" {
		opts.Category = "code"
	}

	baseScope, err := scope.Normalize(opts.Scope)
	if err != nil {
		return nil, err
	}

	gitCtx := gitscope.Detect(absRoot)
	repoName := gitCtx.RepoName
	if repoName == "" {
		repoName = filepath.Base(absRoot)
	}
	// Dedicated index session isolates mutable code chunks from episodic Merkle hash chains.
	indexSession := "index:" + repoName

	// Load existing hash-incremental manifest if store supports it
	var incStore incrementalIndexStore
	existingManifest := make(map[string]sqlite.IndexedFileRecord)
	if mgr != nil && mgr.Store() != nil {
		if s, ok := mgr.Store().(incrementalIndexStore); ok {
			incStore = s
			if m, mErr := s.ListIndexedFiles(ctx, absRoot); mErr == nil {
				existingManifest = m
			}
		}
	}

	// Phase 1: Fast discovery scan with strict symlink rejection
	var candidates []candidateFile
	seenRelPaths := make(map[string]bool)

	walkErr := filepath.Walk(absRoot, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			stats.FilesSkipped++
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// Refuse symlinks fail-closed to prevent repo-escape indexing (e.g. evil.go -> ~/.ssh/id_rsa)
		if fi.Mode()&os.ModeSymlink != 0 {
			stats.FilesSkipped++
			if fi.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		base := fi.Name()
		if fi.IsDir() {
			if defaultSkippedDirs[base] {
				return filepath.SkipDir
			}
			for _, sd := range opts.SkipDirs {
				if base == sd {
					return filepath.SkipDir
				}
			}
			return nil
		}

		stats.FilesScanned++

		// Security: Skip sensitive files
		lowerBase := strings.ToLower(base)
		if sensitiveFileNames[lowerBase] || strings.HasSuffix(lowerBase, ".pem") || strings.HasSuffix(lowerBase, ".key") {
			stats.FilesSkipped++
			return nil
		}

		// Check supported extension
		ext := strings.ToLower(filepath.Ext(base))
		if !supportedExtensions[ext] {
			stats.FilesSkipped++
			return nil
		}

		// Skip oversized or empty files
		if fi.Size() > opts.MaxFileSize || fi.Size() == 0 {
			stats.FilesSkipped++
			return nil
		}

		relPath, rErr := filepath.Rel(absRoot, path)
		if rErr != nil {
			stats.FilesSkipped++
			return nil
		}
		relSlash := filepath.ToSlash(relPath)

		candidates = append(candidates, candidateFile{
			path:    path,
			relPath: relSlash,
			ext:     ext,
		})
		seenRelPaths[relSlash] = true

		if opts.OnProgress != nil && stats.FilesScanned%25 == 0 {
			opts.OnProgress(IndexProgress{
				Phase:        PhaseDiscovering,
				FilesScanned: stats.FilesScanned,
				FilesSkipped: stats.FilesSkipped,
				TotalFiles:   len(candidates),
				Elapsed:      time.Since(start),
			})
		}
		return nil
	})

	if walkErr != nil && walkErr != context.Canceled {
		return stats, walkErr
	}

	totalCandidates := len(candidates)
	if opts.OnProgress != nil {
		opts.OnProgress(IndexProgress{
			Phase:        PhaseDiscovering,
			FilesScanned: stats.FilesScanned,
			FilesSkipped: stats.FilesSkipped,
			TotalFiles:   totalCandidates,
			Elapsed:      time.Since(start),
		})
	}

	// Phase 2: Incremental AST/structural indexing loop
	for _, cand := range candidates {
		if ctx.Err() != nil {
			stats.Duration = time.Since(start)
			return stats, ctx.Err()
		}
		if stats.ChunksStored >= opts.MaxChunks {
			break
		}

		if opts.OnProgress != nil {
			var pct float64
			if totalCandidates > 0 {
				pct = (float64(stats.FilesIndexed+stats.FilesUnchanged) / float64(totalCandidates)) * 100.0
			}
			elapsed := time.Since(start)
			var rate float64
			if elapsed.Seconds() > 0 {
				rate = float64(stats.FilesIndexed+stats.FilesUnchanged) / elapsed.Seconds()
			}
			opts.OnProgress(IndexProgress{
				Phase:        PhaseIndexing,
				CurrentFile:  cand.relPath,
				FilesScanned: stats.FilesScanned,
				TotalFiles:   totalCandidates,
				FilesIndexed: stats.FilesIndexed,
				FilesSkipped: stats.FilesSkipped,
				ChunksStored: stats.ChunksStored,
				MaxChunks:    opts.MaxChunks,
				Redactions:   stats.Redactions,
				Elapsed:      elapsed,
				Rate:         rate,
				Percentage:   pct,
			})
		}

		raw, readErr := readConfinedFile(rootFS, cand.relPath, opts.MaxFileSize)
		if readErr != nil || isBinaryBytes(raw) {
			stats.FilesSkipped++
			continue
		}

		sum := sha256.Sum256(raw)
		shaHex := hex.EncodeToString(sum[:])

		prevRec, existed := existingManifest[cand.relPath]
		if !opts.FullRebuild && existed && prevRec.ContentSHA256 == shaHex {
			stats.FilesUnchanged++
			continue
		}

		// File is new or modified: remove stale chunks first before inserting fresh AST chunks
		if existed && incStore != nil && len(prevRec.ChunkIDs) > 0 {
			_ = incStore.DeleteIndexedChunks(ctx, prevRec.ChunkIDs)
			stats.ChunksPruned += len(prevRec.ChunkIDs)
		}

		chunks := ChunkSource(cand.relPath, cand.ext, raw, opts.ChunkLines, opts.Overlap)
		if len(chunks) == 0 {
			stats.FilesSkipped++
			continue
		}

		fileScope, scErr := scope.ResolveFileScope(absRoot, cand.relPath, baseScope, opts.ScopeFromConfig)
		if scErr != nil {
			return stats, scErr
		}

		var newChunkIDs []string
		fileIndexed := false
		for _, chunk := range chunks {
			if stats.ChunksStored >= opts.MaxChunks {
				break
			}

			sanitized, secErr := security.SanitizeMemory(chunk.Content)
			if secErr != nil {
				continue
			}
			if sanitized.RedactedCount > 0 {
				stats.Redactions += sanitized.RedactedCount
			}

			cat := opts.Category
			if cand.ext == ".md" {
				cat = "documentation"
			}

			header := fmt.Sprintf("[%s:%d-%d]", cand.relPath, chunk.StartLine, chunk.EndLine)
			if chunk.Symbol != "" {
				header = fmt.Sprintf("[%s:%d-%d | %s]", cand.relPath, chunk.StartLine, chunk.EndLine, chunk.Symbol)
			}
			contentFormatted := fmt.Sprintf("%s\n%s", header, sanitized.SanitizedText)

			meta := map[string]string{
				"path":          cand.relPath,
				"lang":          cand.ext,
				"start_line":    fmt.Sprintf("%d", chunk.StartLine),
				"end_line":      fmt.Sprintf("%d", chunk.EndLine),
				"git_repo":      repoName,
				"git_branch":    gitCtx.Branch,
				"indexed_at":    time.Now().UTC().Format(time.RFC3339),
				"index_managed": "true",
			}
			if chunk.Symbol != "" {
				meta["symbol"] = chunk.Symbol
			}
			if chunk.Kind != "" {
				meta["chunk_kind"] = chunk.Kind
			}

			node, remErr := mgr.Remember(ctx, brain.RememberRequest{
				SessionID:  indexSession,
				Category:   cat,
				Scope:      fileScope,
				Content:    contentFormatted,
				Provenance: brain.ProvenanceLocalWorkspace,
				Metadata:   meta,
			})
			if remErr == nil && node != nil {
				stats.ChunksStored++
				newChunkIDs = append(newChunkIDs, node.ID)
				fileIndexed = true
			}
		}

		if fileIndexed {
			stats.FilesIndexed++
			if incStore != nil {
				_ = incStore.UpsertIndexedFile(ctx, sqlite.IndexedFileRecord{
					RepoRoot:      absRoot,
					RelPath:       cand.relPath,
					ContentSHA256: shaHex,
					ChunkIDs:      newChunkIDs,
					IndexedAt:     time.Now(),
				})
			}
		} else {
			stats.FilesSkipped++
		}
	}

	// Phase 3: Prune deleted files from manifest and vector/graph store
	if incStore != nil && ctx.Err() == nil {
		for relPath, rec := range existingManifest {
			if !seenRelPaths[relPath] {
				if err := incStore.PruneIndexedFile(ctx, absRoot, relPath, rec.ChunkIDs); err == nil {
					stats.FilesPruned++
					stats.ChunksPruned += len(rec.ChunkIDs)
				}
			}
		}
	}

	stats.Duration = time.Since(start)

	if opts.OnProgress != nil {
		var finalPct float64 = 100.0
		if totalCandidates > 0 && stats.ChunksStored < opts.MaxChunks {
			finalPct = (float64(stats.FilesIndexed+stats.FilesUnchanged) / float64(totalCandidates)) * 100.0
			if finalPct > 100.0 {
				finalPct = 100.0
			}
		}
		var finalRate float64
		if stats.Duration.Seconds() > 0 {
			finalRate = float64(stats.FilesIndexed+stats.FilesUnchanged) / stats.Duration.Seconds()
		}
		opts.OnProgress(IndexProgress{
			Phase:        PhaseComplete,
			FilesScanned: stats.FilesScanned,
			TotalFiles:   totalCandidates,
			FilesIndexed: stats.FilesIndexed,
			FilesSkipped: stats.FilesSkipped,
			ChunksStored: stats.ChunksStored,
			MaxChunks:    opts.MaxChunks,
			Redactions:   stats.Redactions,
			Elapsed:      stats.Duration,
			Rate:         finalRate,
			Percentage:   finalPct,
			Done:         true,
		})
	}

	return stats, nil
}

func readConfinedFile(root *os.Root, relPath string, maxBytes int64) ([]byte, error) {
	f, err := root.Open(relPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("refusing non-regular file %s", relPath)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("file exceeds max size %d", maxBytes)
	}
	return data, nil
}

func isBinaryBytes(data []byte) bool {
	check := data
	if len(check) > 512 {
		check = check[:512]
	}
	return bytes.IndexByte(check, 0) != -1
}

// chunkFile is retained for backward compatibility with internal tests.
type fileChunk struct {
	StartLine int
	EndLine   int
	Content   string
}

func chunkFile(path string, targetLines, overlap int) ([]fileChunk, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(lines) == 0 {
		return nil, nil
	}

	var chunks []fileChunk
	start := 0
	for start < len(lines) {
		end := start + targetLines
		if end > len(lines) {
			end = len(lines)
		}
		content := strings.TrimSpace(strings.Join(lines[start:end], "\n"))
		if content != "" {
			chunks = append(chunks, fileChunk{
				StartLine: start + 1,
				EndLine:   end,
				Content:   content,
			})
		}
		if end >= len(lines) {
			break
		}
		next := end - overlap
		if next <= start {
			next = end
		}
		start = next
	}
	return chunks, nil
}

func isBinaryFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return true
	}
	defer f.Close()

	buf := make([]byte, 512)
	n, err := f.Read(buf)
	if err != nil && err != io.EOF {
		return true
	}
	return bytes.IndexByte(buf[:n], 0) != -1
}
