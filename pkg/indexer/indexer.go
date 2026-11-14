package indexer

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/gitscope"
	"github.com/bonjoski/coppermind/pkg/security"
)

// IndexOptions configures codebase traversal and chunking.
type IndexOptions struct {
	MaxFileSize int64        // Maximum file size in bytes to index (default: 512KB)
	MaxChunks   int          // Maximum total chunks to create per run (default: 1000)
	SkipDirs    []string     // Extra directory names to skip
	ChunkLines  int          // Target lines per chunk (default: 50)
	Overlap     int          // Overlap lines between chunks (default: 5)
	Category    string       // Target category (default: "code")
	OnProgress  ProgressFunc // Optional callback for real-time indexing progress events
}

// IndexStats reports the outcome of a codebase indexing run.
type IndexStats struct {
	FilesScanned int           `json:"files_scanned"`
	FilesIndexed int           `json:"files_indexed"`
	FilesSkipped int           `json:"files_skipped"`
	ChunksStored int           `json:"chunks_stored"`
	Redactions   int           `json:"redactions"`
	Duration     time.Duration `json:"duration"`
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

// IndexDirectory scans a directory tree, chunks source files, and indexes them into Coppermind.
func IndexDirectory(ctx context.Context, mgr *brain.Manager, rootDir string, opts IndexOptions) (*IndexStats, error) {
	start := time.Now()
	stats := &IndexStats{}

	absRoot, err := filepath.Abs(rootDir)
	if err != nil {
		return nil, fmt.Errorf("invalid root directory %s: %w", rootDir, err)
	}

	info, err := os.Stat(absRoot)
	if err != nil {
		return nil, fmt.Errorf("cannot access root directory %s: %w", absRoot, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("path is not a directory: %s", absRoot)
	}

	if opts.MaxFileSize <= 0 {
		opts.MaxFileSize = 512 * 1024 // 512KB
	}
	if opts.MaxChunks <= 0 {
		opts.MaxChunks = 1000
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

	scope := gitscope.Detect(absRoot)
	branch := scope.Branch
	if branch == "" {
		branch = filepath.Base(absRoot)
	}

	// Phase 1: Fast discovery scan to establish candidate file manifest
	var candidates []candidateFile

	walkErr := filepath.Walk(absRoot, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			stats.FilesSkipped++
			return nil
		}

		if ctx.Err() != nil {
			return ctx.Err()
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

		// Skip oversized files
		if fi.Size() > opts.MaxFileSize || fi.Size() == 0 {
			stats.FilesSkipped++
			return nil
		}

		// Check for binary content (null bytes in first 512 bytes)
		if isBinaryFile(path) {
			stats.FilesSkipped++
			return nil
		}

		relPath, rErr := filepath.Rel(absRoot, path)
		if rErr != nil {
			relPath = path
		}

		candidates = append(candidates, candidateFile{
			path:    path,
			relPath: relPath,
			ext:     ext,
		})

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

	// Phase 2: Active indexing loop
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
				pct = (float64(stats.FilesIndexed) / float64(totalCandidates)) * 100.0
			}
			elapsed := time.Since(start)
			var rate float64
			if elapsed.Seconds() > 0 {
				rate = float64(stats.FilesIndexed) / elapsed.Seconds()
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

		chunks, chunkErr := chunkFile(cand.path, opts.ChunkLines, opts.Overlap)
		if chunkErr != nil {
			stats.FilesSkipped++
			continue
		}

		fileIndexed := false
		for _, chunk := range chunks {
			if stats.ChunksStored >= opts.MaxChunks {
				break
			}

			// Security: Run through credential quarantine & cognitive threat filter
			sanitized, secErr := security.SanitizeMemory(chunk.Content)
			if secErr != nil {
				// Rejected due to raw private key or credential leak
				continue
			}

			if sanitized.RedactedCount > 0 {
				stats.Redactions += sanitized.RedactedCount
			}

			cat := opts.Category
			if cand.ext == ".md" {
				cat = "documentation"
			}

			contentFormatted := fmt.Sprintf("[%s:%d-%d]\n%s", cand.relPath, chunk.StartLine, chunk.EndLine, sanitized.SanitizedText)

			_, remErr := mgr.Remember(ctx, brain.RememberRequest{
				SessionID:  branch,
				Category:   cat,
				Content:    contentFormatted,
				Provenance: brain.ProvenanceLocalWorkspace,
				Metadata: map[string]string{
					"path":       cand.relPath,
					"lang":       cand.ext,
					"start_line": fmt.Sprintf("%d", chunk.StartLine),
					"end_line":   fmt.Sprintf("%d", chunk.EndLine),
					"git_repo":   scope.RepoName,
					"git_branch": scope.Branch,
					"indexed_at": time.Now().UTC().Format(time.RFC3339),
				},
			})

			if remErr == nil {
				stats.ChunksStored++
				fileIndexed = true
			}
		}

		if fileIndexed {
			stats.FilesIndexed++
		} else {
			stats.FilesSkipped++
		}
	}

	stats.Duration = time.Since(start)

	if opts.OnProgress != nil {
		var finalPct float64 = 100.0
		if totalCandidates > 0 && stats.ChunksStored < opts.MaxChunks {
			finalPct = (float64(stats.FilesIndexed) / float64(totalCandidates)) * 100.0
			if finalPct > 100.0 {
				finalPct = 100.0
			}
		}
		var finalRate float64
		if stats.Duration.Seconds() > 0 {
			finalRate = float64(stats.FilesIndexed) / stats.Duration.Seconds()
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

type fileChunk struct {
	StartLine int
	EndLine   int
	Content   string
}

func chunkFile(filePath string, targetLines, overlap int) ([]fileChunk, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	// Allow large lines
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if len(lines) == 0 {
		return nil, nil
	}

	if len(lines) <= targetLines {
		return []fileChunk{
			{
				StartLine: 1,
				EndLine:   len(lines),
				Content:   strings.Join(lines, "\n"),
			},
		}, nil
	}

	var chunks []fileChunk
	step := targetLines - overlap
	if step <= 0 {
		step = targetLines
	}

	for i := 0; i < len(lines); i += step {
		end := i + targetLines
		if end > len(lines) {
			end = len(lines)
		}

		chunkLines := lines[i:end]
		content := strings.TrimSpace(strings.Join(chunkLines, "\n"))
		if content != "" {
			chunks = append(chunks, fileChunk{
				StartLine: i + 1,
				EndLine:   end,
				Content:   content,
			})
		}

		if end == len(lines) {
			break
		}
	}

	return chunks, nil
}

func isBinaryFile(filePath string) bool {
	f, err := os.Open(filePath)
	if err != nil {
		return true
	}
	defer f.Close()

	header := make([]byte, 512)
	n, err := f.Read(header)
	if err != nil && err != io.EOF {
		return true
	}

	// If null byte exists in first 512 bytes, treat as binary
	return bytes.IndexByte(header[:n], 0) != -1
}
