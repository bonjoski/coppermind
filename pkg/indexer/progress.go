package indexer

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/mattn/go-isatty"
)

// IndexPhase represents the distinct phases of the indexing pipeline.
type IndexPhase string

const (
	// PhaseDiscovering indicates fast filesystem tree traversal and candidate file enumeration.
	PhaseDiscovering IndexPhase = "discovering"
	// PhaseIndexing indicates active chunking, redaction sanitization, embedding, and storage.
	PhaseIndexing IndexPhase = "indexing"
	// PhaseComplete indicates all files have been processed or limits reached.
	PhaseComplete IndexPhase = "complete"
)

// IndexProgress captures a point-in-time telemetry snapshot of codebase indexing.
type IndexProgress struct {
	Phase        IndexPhase    `json:"phase"`
	CurrentFile  string        `json:"current_file,omitempty"`
	FilesScanned int           `json:"files_scanned"`
	TotalFiles   int           `json:"total_files"`   // Total candidate files to index
	FilesIndexed int           `json:"files_indexed"` // Successfully indexed files
	FilesSkipped int           `json:"files_skipped"` // Skipped files (sensitive, binary, oversized)
	ChunksStored int           `json:"chunks_stored"`
	MaxChunks    int           `json:"max_chunks"`
	Redactions   int           `json:"redactions"`
	Elapsed      time.Duration `json:"elapsed"`
	Rate         float64       `json:"rate"`       // Files indexed per second
	Percentage   float64       `json:"percentage"` // 0.0 - 100.0
	Done         bool          `json:"done"`
}

// ProgressFunc is a consumer callback for real-time indexing progress events.
type ProgressFunc func(progress IndexProgress)

// MeterOptions configures the visual presentation and behavior of ProgressMeter.
type MeterOptions struct {
	Writer      io.Writer
	ForceTTY    bool          // Force ANSI interactive terminal mode
	DisableTTY  bool          // Force non-interactive / plain log mode
	Quiet       bool          // Completely suppress output
	BarWidth    int           // Character width of the progress bar (default: 20)
	MinInterval time.Duration // Throttling interval for TTY refreshes (default: 35ms)
}

// ProgressMeter renders a real-time progress bar to an interactive terminal
// or throttled plain-text milestone logs to non-interactive streams / CI environments.
type ProgressMeter struct {
	out         io.Writer
	isTTY       bool
	quiet       bool
	barWidth    int
	minInterval time.Duration
	lastRender  time.Time
	lastLogPct  int
	lastPhase   IndexPhase
	mu          sync.Mutex
	closed      bool
}

// NewProgressMeter initializes a new progress meter adhering to terminal TTY conventions.
func NewProgressMeter(opts MeterOptions) *ProgressMeter {
	w := opts.Writer
	if w == nil {
		w = os.Stdout
	}

	isTTY := false
	if opts.ForceTTY {
		isTTY = true
	} else if !opts.DisableTTY {
		if f, ok := w.(*os.File); ok {
			isTTY = isatty.IsTerminal(f.Fd()) || isatty.IsCygwinTerminal(f.Fd())
		}
	}

	barWidth := opts.BarWidth
	if barWidth <= 0 {
		barWidth = 20
	}

	minInterval := opts.MinInterval
	if minInterval <= 0 {
		minInterval = 35 * time.Millisecond
	}

	return &ProgressMeter{
		out:         w,
		isTTY:       isTTY,
		quiet:       opts.Quiet,
		barWidth:    barWidth,
		minInterval: minInterval,
		lastLogPct:  -1,
	}
}

// Update processes an IndexProgress event and updates the terminal or log stream.
func (m *ProgressMeter) Update(p IndexProgress) {
	if m.quiet {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return
	}

	now := time.Now()

	if m.isTTY {
		// In interactive terminal mode, throttle high-frequency redraws unless completing
		if !p.Done && p.Phase == m.lastPhase && now.Sub(m.lastRender) < m.minInterval {
			return
		}
		m.lastRender = now
		m.lastPhase = p.Phase
		m.renderTTY(p)
	} else {
		// In non-interactive mode (pipes, CI, subagent logs), emit throttled milestone lines
		m.renderNonTTY(p)
	}
}

// renderTTY prints a clean ANSI-formatted in-place progress bar.
func (m *ProgressMeter) renderTTY(p IndexProgress) {
	switch p.Phase {
	case PhaseDiscovering:
		fmt.Fprintf(m.out, "\r\033[K🔍 [1/2] Discovering source files... (%d scanned, %d candidates)",
			p.FilesScanned, p.TotalFiles)

	case PhaseIndexing:
		pct := p.Percentage
		if pct < 0 {
			pct = 0
		} else if pct > 100 {
			pct = 100
		}

		filled := int((pct / 100.0) * float64(m.barWidth))
		if filled > m.barWidth {
			filled = m.barWidth
		}
		empty := m.barWidth - filled

		bar := strings.Repeat("█", filled) + strings.Repeat("░", empty)

		// Sanitize and truncate current filename to prevent terminal control injection or line wrapping
		sanitizedFile := sanitizeTerminalString(p.CurrentFile)
		if len(sanitizedFile) > 28 {
			sanitizedFile = "..." + sanitizedFile[len(sanitizedFile)-25:]
		}

		rateStr := ""
		if p.Rate > 0 {
			rateStr = fmt.Sprintf(" [%.1f files/s]", p.Rate)
		}

		fmt.Fprintf(m.out, "\r\033[K📦 [2/2] Indexing: [%s] %5.1f%% (%d/%d files, %d chunks)%s %s",
			bar, pct, p.FilesIndexed, p.TotalFiles, p.ChunksStored, rateStr, sanitizedFile)

	case PhaseComplete:
		// Clear current line so subsequent summary prints cleanly
		fmt.Fprint(m.out, "\r\033[K")
	}
}

// renderNonTTY prints clean milestone logs at 10% intervals without ANSI escape codes.
func (m *ProgressMeter) renderNonTTY(p IndexProgress) {
	if p.Phase == PhaseDiscovering {
		// Log discovery completion once
		if m.lastPhase != PhaseDiscovering && p.TotalFiles > 0 {
			m.lastPhase = PhaseDiscovering
			fmt.Fprintf(m.out, "[index] Discovered %d candidate files to index (%d scanned, %d skipped)\n",
				p.TotalFiles, p.FilesScanned, p.FilesSkipped)
		}
		return
	}

	if p.Phase == PhaseIndexing {
		m.lastPhase = PhaseIndexing
		currPctBucket := int(p.Percentage / 10.0) * 10
		if currPctBucket > m.lastLogPct {
			m.lastLogPct = currPctBucket
			fmt.Fprintf(m.out, "[index] Progress: %5.1f%% (%d/%d files, %d chunks stored, %d redactions)\n",
				p.Percentage, p.FilesIndexed, p.TotalFiles, p.ChunksStored, p.Redactions)
		}
		return
	}

	if p.Phase == PhaseComplete {
		m.lastPhase = PhaseComplete
		if m.lastLogPct < 100 {
			m.lastLogPct = 100
			fmt.Fprintf(m.out, "[index] Progress: 100.0%% (%d/%d files, %d chunks stored, %d redactions)\n",
				p.FilesIndexed, p.TotalFiles, p.ChunksStored, p.Redactions)
		}
	}
}

// Close finalizes the meter, clearing any dangling ANSI lines.
func (m *ProgressMeter) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil
	}
	m.closed = true

	if !m.quiet && m.isTTY {
		fmt.Fprint(m.out, "\r\033[K")
	}
	return nil
}

// sanitizeTerminalString strips ASCII control characters and ANSI escape sequences
// to protect the host terminal against terminal injection vulnerabilities.
func sanitizeTerminalString(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || unicode.Is(unicode.Cc, r) {
			continue // Drop control characters
		}
		sb.WriteRune(r)
	}
	return sb.String()
}
