package indexer

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
)

// CodeChunk represents a semantically bounded slice of a source or documentation file.
type CodeChunk struct {
	StartLine int
	EndLine   int
	Symbol    string // e.g. "Server.handleToolsCall" or "README.md > Quickstart"
	Kind      string // "func", "type", "decl", "markdown_section", "block"
	Content   string
}

const maxASTFuncLines = 120

// ChunkSource selects the best structural chunker for the given file extension:
//   - .go: stdlib go/parser + go/ast symbol chunking (falls back gracefully on syntax error)
//   - .md: heading-tree breadcrumb chunking (never splits inside fenced code blocks)
//   - other code: declaration-boundary structural chunking
func ChunkSource(relPath, ext string, src []byte, targetLines, overlap int) []CodeChunk {
	if len(src) == 0 {
		return nil
	}
	if targetLines <= 0 {
		targetLines = 50
	}
	if overlap < 0 {
		overlap = 5
	}

	switch strings.ToLower(ext) {
	case ".go":
		if chunks, err := chunkGoAST(relPath, src); err == nil && len(chunks) > 0 {
			return chunks
		}
		return chunkStructural(src, targetLines, overlap)
	case ".md":
		if chunks := chunkMarkdownTree(relPath, string(src), targetLines); len(chunks) > 0 {
			return chunks
		}
		return chunkStructural(src, targetLines, overlap)
	default:
		return chunkStructural(src, targetLines, overlap)
	}
}

func chunkGoAST(relPath string, src []byte) ([]CodeChunk, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, relPath, src, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(src), "\n")
	pkgName := file.Name.Name
	var chunks []CodeChunk

	sliceLines := func(startLine, endLine int) string {
		if startLine < 1 {
			startLine = 1
		}
		if endLine > len(lines) {
			endLine = len(lines)
		}
		if startLine > endLine {
			return ""
		}
		return strings.Join(lines[startLine-1:endLine], "\n")
	}

	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			startPos := d.Pos()
			if d.Doc != nil && d.Doc.Pos() < startPos {
				startPos = d.Doc.Pos()
			}
			startLine := fset.Position(startPos).Line
			endLine := fset.Position(d.End()).Line

			sym := pkgName + "." + d.Name.Name
			if d.Recv != nil && len(d.Recv.List) > 0 {
				recvType := exprTypeName(d.Recv.List[0].Type)
				if recvType != "" {
					sym = recvType + "." + d.Name.Name
				}
			}

			if endLine-startLine+1 <= maxASTFuncLines {
				if content := strings.TrimSpace(sliceLines(startLine, endLine)); content != "" {
					chunks = append(chunks, CodeChunk{
						StartLine: startLine,
						EndLine:   endLine,
						Symbol:    sym,
						Kind:      "func",
						Content:   content,
					})
				}
				continue
			}

			// Split oversized function cleanly on statement windows while preserving signature header.
			sigLine := fset.Position(d.Pos()).Line
			sigHeader := strings.TrimSpace(sliceLines(sigLine, sigLine))
			curStart := startLine
			for curStart <= endLine {
				curEnd := curStart + maxASTFuncLines - 1
				if curEnd > endLine {
					curEnd = endLine
				}
				body := strings.TrimSpace(sliceLines(curStart, curEnd))
				if curStart > sigLine && sigHeader != "" {
					body = "// " + sigHeader + " (continued)\n" + body
				}
				if body != "" {
					chunks = append(chunks, CodeChunk{
						StartLine: curStart,
						EndLine:   curEnd,
						Symbol:    sym,
						Kind:      "func",
						Content:   body,
					})
				}
				if curEnd >= endLine {
					break
				}
				curStart = curEnd - 4
			}

		case *ast.GenDecl:
			if d.Tok == token.IMPORT {
				continue
			}
			startPos := d.Pos()
			if d.Doc != nil && d.Doc.Pos() < startPos {
				startPos = d.Doc.Pos()
			}
			startLine := fset.Position(startPos).Line
			endLine := fset.Position(d.End()).Line

			sym := pkgName + "." + strings.ToLower(d.Tok.String())
			if len(d.Specs) > 0 {
				if ts, ok := d.Specs[0].(*ast.TypeSpec); ok && ts.Name != nil {
					sym = pkgName + "." + ts.Name.Name
				} else if vs, ok := d.Specs[0].(*ast.ValueSpec); ok && len(vs.Names) > 0 {
					sym = pkgName + "." + vs.Names[0].Name
				}
			}
			if content := strings.TrimSpace(sliceLines(startLine, endLine)); content != "" {
				chunks = append(chunks, CodeChunk{
					StartLine: startLine,
					EndLine:   endLine,
					Symbol:    sym,
					Kind:      strings.ToLower(d.Tok.String()),
					Content:   content,
				})
			}
		}
	}
	return chunks, nil
}

func exprTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return exprTypeName(t.X)
	case *ast.IndexExpr:
		return exprTypeName(t.X)
	case *ast.IndexListExpr:
		return exprTypeName(t.X)
	default:
		return ""
	}
}

func chunkMarkdownTree(relPath, text string, maxLines int) []CodeChunk {
	if maxLines < 40 {
		maxLines = 60
	}
	lines := strings.Split(text, "\n")
	var chunks []CodeChunk

	headings := make([]string, 5) // 1..4
	inFence := false
	fenceChar := ""
	secStart := 1
	var buf []string

	breadcrumb := func() string {
		parts := []string{relPath}
		for lvl := 1; lvl <= 4; lvl++ {
			if headings[lvl] != "" {
				parts = append(parts, headings[lvl])
			}
		}
		return strings.Join(parts, " > ")
	}

	flush := func(endLine int) {
		body := strings.TrimSpace(strings.Join(buf, "\n"))
		if body == "" {
			buf = nil
			return
		}
		bc := breadcrumb()
		chunks = append(chunks, CodeChunk{
			StartLine: secStart,
			EndLine:   endLine,
			Symbol:    bc,
			Kind:      "markdown_section",
			Content:   fmt.Sprintf("[%s]\n%s", bc, body),
		})
		buf = nil
	}

	for idx, line := range lines {
		lineNum := idx + 1
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~") {
			marker := trimmed[:3]
			if !inFence {
				inFence = true
				fenceChar = marker
			} else if marker == fenceChar {
				inFence = false
				fenceChar = ""
			}
			buf = append(buf, line)
			continue
		}

		if !inFence && strings.HasPrefix(trimmed, "#") {
			lvl := 0
			for lvl < len(trimmed) && trimmed[lvl] == '#' {
				lvl++
			}
			if lvl >= 1 && lvl <= 4 && lvl < len(trimmed) && trimmed[lvl] == ' ' {
				flush(lineNum - 1)
				title := strings.TrimSpace(trimmed[lvl+1:])
				headings[lvl] = title
				for clearLvl := lvl + 1; clearLvl <= 4; clearLvl++ {
					headings[clearLvl] = ""
				}
				secStart = lineNum
				buf = append(buf, line)
				continue
			}
		}

		buf = append(buf, line)
		// Never split mid-code-fence; split oversized markdown sections cleanly at blank lines.
		if !inFence && len(buf) >= maxLines && trimmed == "" {
			flush(lineNum)
			secStart = lineNum + 1
		}
	}
	flush(len(lines))
	return chunks
}

var declPrefixes = []string{
	"func ", "def ", "async def ", "class ", "fn ", "pub fn ", "async fn ",
	"impl ", "struct ", "pub struct ", "export function ", "export class ",
	"export interface ", "export const ", "function ", "interface ", "type ",
}

func isStructuralBoundary(line string) bool {
	trimmed := strings.TrimSpace(line)
	for _, p := range declPrefixes {
		if strings.HasPrefix(trimmed, p) {
			return true
		}
	}
	return false
}

func chunkStructural(src []byte, targetLines, overlap int) []CodeChunk {
	lines := strings.Split(string(src), "\n")
	if len(lines) == 0 {
		return nil
	}
	minLines := targetLines * 6 / 10
	if minLines < 20 {
		minLines = 20
	}
	maxLines := targetLines * 18 / 10
	if maxLines < targetLines+20 {
		maxLines = targetLines + 20
	}

	var chunks []CodeChunk
	start := 0
	for start < len(lines) {
		end := start + targetLines
		if end >= len(lines) {
			end = len(lines)
		} else {
			// Look ahead/behind for a clean structural boundary
			best := end
			limit := start + maxLines
			if limit > len(lines) {
				limit = len(lines)
			}
			found := false
			for i := start + minLines; i < limit; i++ {
				if isStructuralBoundary(lines[i]) {
					best = i
					found = true
					break
				}
			}
			if !found {
				for i := end; i > start+minLines; i-- {
					if strings.TrimSpace(lines[i]) == "" {
						best = i
						break
					}
				}
			}
			end = best
		}

		content := strings.TrimSpace(strings.Join(lines[start:end], "\n"))
		if content != "" {
			chunks = append(chunks, CodeChunk{
				StartLine: start + 1,
				EndLine:   end,
				Kind:      "block",
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
	return chunks
}
