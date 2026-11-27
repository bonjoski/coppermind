// Package memguard provides Coppermind's self-contained, in-process cognitive
// memory firewall, Unicode/encoding cloaking normalizer, delimiter sanitizer,
// and semantic provenance taint engine with zero external repository dependencies.
package memguard

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	// ShingleSize is the sliding window byte length used for taint shingle indexing.
	ShingleSize = 8
	// EntropyThreshold is the Shannon entropy cutoff (bits/byte) for egress suspicion.
	EntropyThreshold = 5.2
	// MinLengthForEntropyTest is the minimum payload byte length evaluated for entropy.
	MinLengthForEntropyTest = 24
)

var (
	// ErrInvalidTaintLevel is returned when a taint level string is unrecognized.
	ErrInvalidTaintLevel = errors.New("invalid taint level")
	// ErrInvalidPrivilegeLevel is returned when a privilege level string is unrecognized.
	ErrInvalidPrivilegeLevel = errors.New("invalid privilege level")
	// ErrTaintGateViolation is returned when tainted context attempts direct high-privilege flow.
	ErrTaintGateViolation = errors.New("tainted input cannot flow directly to elevated privilege agent without firewall sanitization")
)

// EgressTools lists tool names classified as external network or exfiltration pathways.
var EgressTools = map[string]bool{
	"fetch":        true,
	"curl":         true,
	"http_request": true,
	"webhook":      true,
	"send_message": true,
	"post":         true,
	"git_push":     true,
	"dns_query":    true,
}

// SensitivePatterns defines filename and extension patterns that trigger automatic tainting.
var SensitivePatterns = []string{
	".env",
	"*.env",
	".env.*",
	"*.pem",
	"*.key",
	"*.pkcs12",
	"*.pfx",
	"*id_rsa*",
	"*id_ed25519*",
	"*id_ecdsa*",
	"credentials.json",
	"secret*",
	"*token*",
	"*passwd*",
	"shadow",
}

// TaintLevel defines the provenance security classification of context data.
type TaintLevel string

const (
	// TRUST_LOCAL_WORKSPACE represents verified local source code and authorized local configuration.
	TRUST_LOCAL_WORKSPACE TaintLevel = "TRUST_LOCAL_WORKSPACE"
	// TAINT_SHARED_DOC represents shared repository history (e.g. git diffs/commits) or collaborative docs.
	TAINT_SHARED_DOC TaintLevel = "TAINT_SHARED_DOC"
	// TAINT_EXTERNAL_USER represents data originating from PR comments, issue descriptions, or external user chat.
	TAINT_EXTERNAL_USER TaintLevel = "TAINT_EXTERNAL_USER"
	// TAINT_UNTRUSTED_WEB represents web crawls, scraper output, documentation, and external API responses.
	TAINT_UNTRUSTED_WEB TaintLevel = "TAINT_UNTRUSTED_WEB"
)

// String returns the canonical string representation of the TaintLevel.
func (t TaintLevel) String() string {
	return string(t)
}

// IsValid checks whether the TaintLevel is recognized.
func (t TaintLevel) IsValid() bool {
	switch t {
	case TRUST_LOCAL_WORKSPACE, TAINT_SHARED_DOC, TAINT_EXTERNAL_USER, TAINT_UNTRUSTED_WEB:
		return true
	default:
		return false
	}
}

// Severity returns an integer rank for taint comparisons: higher number = higher risk.
// Unrecognized values fail closed to maximum severity.
func (t TaintLevel) Severity() int {
	switch t {
	case TRUST_LOCAL_WORKSPACE:
		return 0
	case TAINT_SHARED_DOC:
		return 1
	case TAINT_EXTERNAL_USER:
		return 2
	case TAINT_UNTRUSTED_WEB:
		return 3
	default:
		return 3
	}
}

// ParseTaintLevel parses a string into a validated TaintLevel.
func ParseTaintLevel(s string) (TaintLevel, error) {
	t := TaintLevel(strings.ToUpper(strings.TrimSpace(s)))
	if !t.IsValid() {
		return TAINT_UNTRUSTED_WEB, fmt.Errorf("%w: %q", ErrInvalidTaintLevel, s)
	}
	return t, nil
}

// MergeTaints calculates the propagated taint when multiple inputs are combined.
// Propagation rule: the resulting taint level adopts the highest severity of all inputs.
// Empty or invalid inputs fail closed to TAINT_UNTRUSTED_WEB.
func MergeTaints(levels ...TaintLevel) TaintLevel {
	if len(levels) == 0 {
		return TAINT_UNTRUSTED_WEB
	}
	highest := TRUST_LOCAL_WORKSPACE
	for _, l := range levels {
		if !l.IsValid() {
			return TAINT_UNTRUSTED_WEB
		}
		if l.Severity() > highest.Severity() {
			highest = l
		}
	}
	return highest
}

// PrivilegeLevel defines the tool execution capability of a receiving agent.
type PrivilegeLevel string

const (
	PRIVILEGE_LOW    PrivilegeLevel = "LOW"    // Read-only analysis, indexing, planning
	PRIVILEGE_MEDIUM PrivilegeLevel = "MEDIUM" // Sandboxed code modification, unit test execution
	PRIVILEGE_HIGH   PrivilegeLevel = "HIGH"   // Shell execution, git push, deployment, cloud credentials
)

// ParsePrivilegeLevel parses a string into a validated PrivilegeLevel.
func ParsePrivilegeLevel(s string) (PrivilegeLevel, error) {
	switch PrivilegeLevel(strings.ToUpper(strings.TrimSpace(s))) {
	case PRIVILEGE_LOW:
		return PRIVILEGE_LOW, nil
	case PRIVILEGE_MEDIUM:
		return PRIVILEGE_MEDIUM, nil
	case PRIVILEGE_HIGH:
		return PRIVILEGE_HIGH, nil
	default:
		return PRIVILEGE_HIGH, fmt.Errorf("%w: %q", ErrInvalidPrivilegeLevel, s)
	}
}

// DirectAccessAllowed returns true if context with taint t can flow directly to
// an agent with privilege p without firewall intervention.
func DirectAccessAllowed(t TaintLevel, p PrivilegeLevel) bool {
	if !t.IsValid() {
		return false
	}
	if t == TRUST_LOCAL_WORKSPACE {
		return true
	}
	if p == PRIVILEGE_HIGH {
		return false
	}
	if p == PRIVILEGE_MEDIUM && t.Severity() >= TAINT_EXTERNAL_USER.Severity() {
		return false
	}
	return p == PRIVILEGE_LOW
}

// TaintSource identifies the origin category of tainted information.
type TaintSource string

const (
	SourceSecretFile TaintSource = "SECRET_FILE"
	SourcePrivateKey TaintSource = "PRIVATE_KEY"
	SourceEnvVar     TaintSource = "ENV_VAR"
)

// TaintRecord tracks sensitive data slices and derived shingles in memory.
type TaintRecord struct {
	ID          string      `json:"id"`
	Source      TaintSource `json:"source"`
	Path        string      `json:"path"`
	Fingerprint [32]byte    `json:"fingerprint"`
	Shingles    [][]byte    `json:"shingles"`
	CreatedAt   time.Time   `json:"created_at"`
}

// TaintedEnvelope encapsulates data with provenance taint tracking and agent lineage.
type TaintedEnvelope struct {
	Content   string     `json:"content"`
	Taint     TaintLevel `json:"taint"`
	Source    string     `json:"source"`
	Lineage   []string   `json:"lineage"`
	Timestamp time.Time  `json:"timestamp"`
}

// NewTaintedEnvelope constructs a new envelope with validated taint.
func NewTaintedEnvelope(content string, taint TaintLevel, source string, originAgent string) (*TaintedEnvelope, error) {
	if !taint.IsValid() {
		return nil, fmt.Errorf("%w: %q", ErrInvalidTaintLevel, taint)
	}
	lineage := make([]string, 0, 1)
	if originAgent != "" {
		lineage = append(lineage, originAgent)
	}
	return &TaintedEnvelope{
		Content:   content,
		Taint:     taint,
		Source:    source,
		Lineage:   lineage,
		Timestamp: time.Now().UTC(),
	}, nil
}

// Propagate transforms the content while preserving or escalating taint and recording lineage.
func (e *TaintedEnvelope) Propagate(newContent string, currentAgent string, additionalTaint ...TaintLevel) *TaintedEnvelope {
	levels := make([]TaintLevel, 0, 1+len(additionalTaint))
	levels = append(levels, e.Taint)
	levels = append(levels, additionalTaint...)

	nextLineage := make([]string, len(e.Lineage), len(e.Lineage)+1)
	copy(nextLineage, e.Lineage)
	if currentAgent != "" {
		nextLineage = append(nextLineage, currentAgent)
	}
	return &TaintedEnvelope{
		Content:   newContent,
		Taint:     MergeTaints(levels...),
		Source:    e.Source,
		Lineage:   nextLineage,
		Timestamp: time.Now().UTC(),
	}
}

// TaintLedger maintains thread-safe, session-partitioned dynamic taint graphs.
type TaintLedger struct {
	mu       sync.RWMutex
	sessions map[string][]*TaintRecord
}

// NewTaintLedger creates an active taint ledger instance.
func NewTaintLedger() *TaintLedger {
	return &TaintLedger{
		sessions: make(map[string][]*TaintRecord),
	}
}

// RegisterTaint tags and indexes a sensitive data buffer for a session.
func (l *TaintLedger) RegisterTaint(sessionID string, source TaintSource, path string, data []byte) (*TaintRecord, error) {
	if strings.TrimSpace(sessionID) == "" {
		return nil, errors.New("sessionID cannot be empty")
	}
	fp := sha256.Sum256(data)
	shingles := extractShingles(data, ShingleSize)
	rec := &TaintRecord{
		ID:          hex.EncodeToString(fp[:8]),
		Source:      source,
		Path:        path,
		Fingerprint: fp,
		Shingles:    shingles,
		CreatedAt:   time.Now().UTC(),
	}

	l.mu.Lock()
	l.sessions[sessionID] = append(l.sessions[sessionID], rec)
	l.mu.Unlock()
	return rec, nil
}

// EvaluateEgress scans an outgoing payload for tainted shingles or suspicious entropy.
// Returns (allowed, reason).
func (l *TaintLedger) EvaluateEgress(sessionID string, toolName string, payload []byte) (bool, string) {
	if !IsEgressTool(toolName) {
		return true, ""
	}

	l.mu.RLock()
	records := append([]*TaintRecord(nil), l.sessions[sessionID]...)
	l.mu.RUnlock()

	for _, rec := range records {
		for _, sh := range rec.Shingles {
			if len(sh) >= ShingleSize && bytes.Contains(payload, sh) {
				return false, fmt.Sprintf("egress blocked: payload matches tainted shingle from %s (%s)", rec.Path, rec.Source)
			}
		}
	}

	if len(records) > 0 && len(payload) >= MinLengthForEntropyTest {
		if ent := CalculateShannonEntropy(payload); ent >= EntropyThreshold {
			return false, fmt.Sprintf("egress blocked: high-entropy payload (%.2f bits/byte) in tainted session", ent)
		}
	}

	return true, ""
}

// ClearSession purges taint records for a completed subagent worktree session.
func (l *TaintLedger) ClearSession(sessionID string) {
	l.mu.Lock()
	delete(l.sessions, sessionID)
	l.mu.Unlock()
}

// IsEgressTool checks if the executed tool transmits data outside the local sandbox.
func IsEgressTool(toolName string) bool {
	return EgressTools[strings.ToLower(strings.TrimSpace(toolName))]
}

// IsSensitivePath checks if a requested filesystem path matches known secret patterns.
func IsSensitivePath(path string) bool {
	base := strings.ToLower(filepath.Base(strings.TrimSpace(path)))
	if base == "" || base == "." || base == "/" {
		return false
	}
	for _, pat := range SensitivePatterns {
		if matched, err := filepath.Match(strings.ToLower(pat), base); err == nil && matched {
			return true
		}
	}
	return false
}

// CalculateShannonEntropy computes information entropy for a byte slice (in bits per byte).
func CalculateShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	total := float64(len(data))
	var entropy float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func extractShingles(data []byte, size int) [][]byte {
	if len(data) < size || size <= 0 {
		return nil
	}
	const maxShingles = 256
	step := 1
	if len(data)-size+1 > maxShingles {
		step = (len(data) - size + 1) / maxShingles
		if step < 1 {
			step = 1
		}
	}
	seen := make(map[string]struct{}, maxShingles)
	out := make([][]byte, 0, min(maxShingles, len(data)-size+1))
	for i := 0; i+size <= len(data) && len(out) < maxShingles; i += step {
		chunk := data[i : i+size]
		if len(bytes.TrimSpace(chunk)) < size/2 {
			continue
		}
		key := string(chunk)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		cp := make([]byte, size)
		copy(cp, chunk)
		out = append(out, cp)
	}
	return out
}
