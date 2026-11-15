package seeder

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bonjoski/coppermind/pkg/authz"
	"github.com/bonjoski/coppermind/pkg/brain"
)

// DocumentChunk represents a parsed section of markdown.
type DocumentChunk struct {
	SessionID  string
	Category   string
	Title      string
	Content    string
	Provenance brain.ProvenanceTier
	Metadata   map[string]string
}

// IngestFile parses a markdown file into semantic chunks and persists them into brain.Manager.
func IngestFile(ctx context.Context, mgr *brain.Manager, filePath string, defaultCategory string) (int, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return 0, fmt.Errorf("failed to open file %s: %w", filePath, err)
	}
	defer file.Close()

	base := filepath.Base(filePath)
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)

	// Determine session ID based on file name or parent dir
	sessionID := name
	if strings.Contains(name, "-") {
		parts := strings.Split(name, "-")
		if len(parts) > 1 && len(parts[0]) == 2 { // e.g. 01-fabrial -> fabrial
			sessionID = strings.Join(parts[1:], "-")
		}
	}

	chunks := parseMarkdownChunks(file, sessionID, defaultCategory, filePath)
	ingested := 0

	for _, chunk := range chunks {
		if len(strings.TrimSpace(chunk.Content)) < 30 {
			continue
		}

		tier := authz.TierToString(authz.CategoryToDefaultTier(chunk.Category))
		_, err := mgr.Remember(ctx, brain.RememberRequest{
			SessionID:       chunk.SessionID,
			Category:        chunk.Category,
			Content:         chunk.Content,
			Provenance:      brain.ProvenanceLocalWorkspace,
			Metadata:        chunk.Metadata,
			AuthorityTier:   tier,
			AuthorRole:      "architect",
			LifecycleStatus: string(authz.StatusActive),
		})
		if err != nil {
			return ingested, fmt.Errorf("failed to ingest chunk %q from %s: %w", chunk.Title, filePath, err)
		}
		ingested++
	}

	return ingested, nil
}

// IngestDirectory traverses rootDir, ingesting all .md files.
func IngestDirectory(ctx context.Context, mgr *brain.Manager, rootDir string, defaultCategory string) (int, error) {
	total := 0
	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".md" {
			return nil
		}

		cat := defaultCategory
		if strings.Contains(path, "knowledge-base") {
			cat = "knowledge-base"
		} else if strings.Contains(path, "plans/accepted") {
			cat = "accepted-rfc"
		} else if strings.Contains(path, "ecosystem") {
			cat = "ecosystem-architecture"
		}

		count, err := IngestFile(ctx, mgr, path, cat)
		if err != nil {
			return fmt.Errorf("error in %s: %w", path, err)
		}
		total += count
		return nil
	})

	return total, err
}

func parseMarkdownChunks(r *os.File, sessionID, defaultCategory, sourcePath string) []DocumentChunk {
	scanner := bufio.NewScanner(r)
	var chunks []DocumentChunk

	var currentTitle string
	var currentLines []string
	inFrontmatter := false
	frontmatterDone := false
	lineNum := 0

	flush := func() {
		if len(currentLines) == 0 {
			return
		}
		content := strings.TrimSpace(strings.Join(currentLines, "\n"))
		if len(content) > 0 {
			title := currentTitle
			if title == "" {
				title = filepath.Base(sourcePath)
			}
			chunks = append(chunks, DocumentChunk{
				SessionID:  sessionID,
				Category:   defaultCategory,
				Title:      title,
				Content:    fmt.Sprintf("[%s] %s\n%s", title, sessionID, content),
				Provenance: brain.ProvenanceLocalWorkspace,
				Metadata: map[string]string{
					"source_file": filepath.Base(sourcePath),
					"title":       title,
				},
			})
		}
		currentLines = nil
	}

	for scanner.Scan() {
		line := scanner.Text()
		lineNum++

		// Skip YAML frontmatter
		if lineNum == 1 && strings.TrimSpace(line) == "---" {
			inFrontmatter = true
			continue
		}
		if inFrontmatter {
			if strings.TrimSpace(line) == "---" {
				inFrontmatter = false
				frontmatterDone = true
			}
			continue
		}

		// Detect markdown headings (## or ###)
		if (strings.HasPrefix(line, "## ") || strings.HasPrefix(line, "### ") || strings.HasPrefix(line, "# ")) && frontmatterDone {
			flush()
			currentTitle = strings.TrimLeft(line, "# ")
			continue
		}

		currentLines = append(currentLines, line)
	}

	flush()
	return chunks
}
