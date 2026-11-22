package capsule

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/bonjoski/coppermind/capsules"
	"github.com/bonjoski/coppermind/pkg/embedding"
	"github.com/bonjoski/coppermind/pkg/security"
	"golang.org/x/text/unicode/norm"
)

const (
	// MentorSchemaVersion is the canonical schema identifier for v1 Security Mentor Capsules.
	MentorSchemaVersion = "bonjoski-mentor-v1"

	// TierMentorCapsule hard-locks all imported mentor cards to advisory Tier 2.5 authority.
	// Mentor cards can never overwrite TIER_0_SOVEREIGN or TIER_1_ARCHITECTURE decisions.
	TierMentorCapsule = "TIER_2_MENTOR_CAPSULE"

	// ProvenanceVerifiedSigned indicates a capsule verified against a valid Ed25519 signature.
	ProvenanceVerifiedSigned = "TRUST_SIGNED_CAPSULE"

	// ProvenanceUnverifiedDraft indicates a local unsigned draft imported with --allow-unsigned.
	ProvenanceUnverifiedDraft = "TAINT_UNVERIFIED_DRAFT"

	// Hard schema and resource bounds (anti-DoS / anti-context-flooding).
	MaxMentorSecureDefaultLen = 180
	MaxMentorWhyOneLinerLen   = 200
	MaxMentorTitleLen         = 120
	MaxMentorAnalogyLen       = 160
	MaxMentorCodeSnippetLen   = 1200
	MaxMentorCapsuleBytes     = 5 * 1024 * 1024 // 5 MB hard cap (zip-bomb defense)
	MaxMentorCardsPerCapsule  = 100
	MaxMentorTriggersPerCard  = 24
)

var (
	mentorWriteGen atomic.Uint64

	ErrMentorValidation      = errors.New("mentor capsule validation failed")
	ErrMentorTierEscalation  = errors.New("mentor capsule authority escalation rejected")
	ErrMentorMerkleMismatch  = errors.New("mentor capsule merkle root mismatch")
	ErrMentorSignatureFailed = errors.New("mentor capsule Ed25519 signature verification failed")
	ErrMentorUnsigned        = errors.New("mentor capsule is unsigned")
	ErrMentorFirewallBlocked = errors.New("mentor capsule blocked by cognitive firewall")
	ErrMentorSecretDetected  = errors.New("mentor capsule blocked by secret quarantine")
	ErrMentorCapsuleTooLarge = errors.New("mentor capsule exceeds maximum 5MB size limit")
	ErrMentorZipSlip         = errors.New("mentor capsule illegal path traversal attempt")
)

// MentorCard represents a single, token-bounded security mental model
// engineered to explain *why* a pattern matters in <= 2 sentences.
type MentorCard struct {
	ID              string   `json:"id"`
	Domain          string   `json:"domain"`
	Triggers        []string `json:"triggers"`
	Title           string   `json:"title"`
	DeterministicEq string   `json:"deterministic_analogy"`
	SecureDefault   string   `json:"secure_default"`
	WhyOneLiner     string   `json:"why_one_liner"`
	CodeSnippet     string   `json:"code_snippet,omitempty"`
	KataRef         string   `json:"kata_ref,omitempty"`
	CWEOrOWASP      string   `json:"cwe_or_owasp,omitempty"`
	AuthorityTier   string   `json:"authority_tier,omitempty"`
}

// MentorCapsuleManifest wraps a signed, versioned collection of MentorCards.
type MentorCapsuleManifest struct {
	SchemaVersion string       `json:"schema_version"`
	Name          string       `json:"name"`
	Version       string       `json:"version"`
	Author        string       `json:"author"`
	CreatedAt     time.Time    `json:"created_at"`
	AuthorityTier string       `json:"authority_tier,omitempty"`
	MerkleRoot    string       `json:"merkle_root"`
	Signature     string       `json:"signature,omitempty"`
	PublicKey     string       `json:"public_key,omitempty"`
	Cards         []MentorCard `json:"cards"`
}

// MentorImportOptions configures verification and trust gating on capsule import.
type MentorImportOptions struct {
	RequiredPubKey ed25519.PublicKey
	AllowUnsigned  bool
}

// ImportedMentorCapsule summarizes an imported mentor capsule stored in SQLite.
type ImportedMentorCapsule struct {
	Name          string    `json:"name"`
	Version       string    `json:"version"`
	SchemaVersion string    `json:"schema_version"`
	Author        string    `json:"author"`
	CreatedAt     time.Time `json:"created_at"`
	ImportedAt    time.Time `json:"imported_at"`
	AuthorityTier string    `json:"authority_tier"`
	Provenance    string    `json:"provenance"`
	MerkleRoot    string    `json:"merkle_root"`
	CardCount     int       `json:"card_count"`
}

// MentorCardRecord is a stored mentor card joined with its parent capsule provenance and vector.
type MentorCardRecord struct {
	Card           MentorCard
	CapsuleName    string
	CapsuleVersion string
	MerklePrefix   string
	AuthorityTier  string
	Provenance     string
	Vector         []float32
}

// SQLiteAccessor is satisfied by sqlite.SQLiteStore for lock-free WAL reads and serialized single-writer transactions.
type SQLiteAccessor interface {
	DB() *sql.DB
	RunWriteTx(ctx context.Context, fn func(tx *sql.Tx) error) error
}

type canonicalMentorCard struct {
	ID              string   `json:"id"`
	Domain          string   `json:"domain"`
	Triggers        []string `json:"triggers"`
	Title           string   `json:"title"`
	DeterministicEq string   `json:"deterministic_analogy"`
	SecureDefault   string   `json:"secure_default"`
	WhyOneLiner     string   `json:"why_one_liner"`
	CodeSnippet     string   `json:"code_snippet,omitempty"`
	KataRef         string   `json:"kata_ref,omitempty"`
	CWEOrOWASP      string   `json:"cwe_or_owasp,omitempty"`
}

// MentorWriteGeneration returns a monotonically increasing generation counter incremented
// after every mentor capsule write commit, enabling zero-hop-tax read caching in MentorLens.
func MentorWriteGeneration() uint64 {
	return mentorWriteGen.Load()
}

// ComputeMerkleRoot computes a deterministic SHA-256 binary Merkle root over cards sorted by ID.
func ComputeMerkleRoot(cards []MentorCard) string {
	if len(cards) == 0 {
		sum := sha256.Sum256(nil)
		return hex.EncodeToString(sum[:])
	}

	sorted := make([]MentorCard, len(cards))
	copy(sorted, cards)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].ID < sorted[j].ID
	})

	level := make([][32]byte, len(sorted))
	for i, c := range sorted {
		triggersCopy := make([]string, len(c.Triggers))
		copy(triggersCopy, c.Triggers)
		canon := canonicalMentorCard{
			ID:              c.ID,
			Domain:          c.Domain,
			Triggers:        triggersCopy,
			Title:           c.Title,
			DeterministicEq: c.DeterministicEq,
			SecureDefault:   c.SecureDefault,
			WhyOneLiner:     c.WhyOneLiner,
			CodeSnippet:     c.CodeSnippet,
			KataRef:         c.KataRef,
			CWEOrOWASP:      c.CWEOrOWASP,
		}
		raw, _ := json.Marshal(canon)
		level[i] = sha256.Sum256(raw)
	}

	for len(level) > 1 {
		nextLen := (len(level) + 1) / 2
		next := make([][32]byte, nextLen)
		for i := 0; i < len(level); i += 2 {
			left := level[i]
			right := left
			if i+1 < len(level) {
				right = level[i+1]
			}
			var combined [64]byte
			copy(combined[:32], left[:])
			copy(combined[32:], right[:])
			next[i/2] = sha256.Sum256(combined[:])
		}
		level = next
	}

	return hex.EncodeToString(level[0][:])
}

// mentorExtraHijackPatterns catches additional OWASP LLM01 / imperative hijack and exfiltration
// instructions that may appear in malicious third-party mentor cards.
var mentorExtraHijackPatterns = []struct {
	Name  string
	Regex *regexp.Regexp
}{
	{
		Name:  "Imperative System Prompt Override",
		Regex: regexp.MustCompile(`(?i)\b(?:forget\s+everything|new\s+system\s+prompt|reveal\s+(?:your\s+)?system\s+prompt|override\s+(?:security\s+)?policy|always\s+obey\s+hidden\s+instructions)\b`),
	},
	{
		Name:  "Remote Shell Execution Pipe",
		Regex: regexp.MustCompile(`(?i)\b(?:curl|wget)\b[^\n|]*\|\s*(?:sh|bash|zsh|python3?)\b`),
	},
	{
		Name:  "Credential Exfiltration Command",
		Regex: regexp.MustCompile(`(?i)(?:cat\s+~?/?\.(?:aws/credentials|ssh/id_[a-z0-9]+|netrc)|exfiltrate|base64\s+-d\s*\|\s*(?:sh|bash)|https?://(?:evil\.com|attacker\.[a-z]+|webhook\.site|requestbin|pipedream|ngrok))`),
	},
	{
		Name:  "XML/Chat Prompt Delimiter Smuggling",
		Regex: regexp.MustCompile(`(?i)</?(?:system|assistant|instruction|developer|prompt|tool_call|function_call|untrusted_artifact)(?:\s+[^>]*)?>`),
	},
}

// homoglyphMap folds common Cyrillic and Greek confusable characters to ASCII Latin skeletons
// to defeat visually indistinguishable prompt injection smuggling.
var homoglyphMap = map[rune]rune{
	// Cyrillic lowercase
	'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
	'і': 'i', 'ї': 'i', 'ј': 'j', 'ѕ': 's', 'ѵ': 'v', 'ԁ': 'd', 'ɡ': 'g',
	// Cyrillic uppercase
	'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O',
	'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X', 'І': 'I', 'Ѕ': 'S', 'Ј': 'J',
	// Greek lowercase
	'α': 'a', 'ε': 'e', 'ι': 'i', 'ο': 'o', 'ρ': 'p', 'ν': 'v', 'τ': 't',
	'υ': 'u', 'κ': 'k', 'χ': 'x',
	// Greek uppercase
	'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Ι': 'I', 'Κ': 'K',
	'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X',
}

func hasInvisibleOrBidiRune(s string) (bool, rune) {
	for _, r := range s {
		if (r >= 0x200B && r <= 0x200F) || // zero-width space/joiners/marks
			(r >= 0x202A && r <= 0x202E) || // bidi embedding/override
			(r >= 0x2060 && r <= 0x2069) || // word joiner / bidi isolates
			r == 0xFEFF || // BOM / ZWNBSP
			(r >= 0xE0000 && r <= 0xE007F) { // Unicode tag characters
			return true, r
		}
	}
	return false, 0
}

func foldHomoglyphs(s string) string {
	normalized := norm.NFKC.String(s)
	var sb strings.Builder
	sb.Grow(len(normalized))
	for _, r := range normalized {
		if mapped, ok := homoglyphMap[r]; ok {
			sb.WriteRune(mapped)
		} else {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

var kebabSlugRegex = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

func isIdentifierField(fieldName string) bool {
	return strings.HasSuffix(fieldName, ".id") ||
		strings.HasSuffix(fieldName, ".domain") ||
		strings.HasSuffix(fieldName, ".kata_ref") ||
		strings.HasSuffix(fieldName, ".cwe_or_owasp") ||
		fieldName == "manifest.name" ||
		fieldName == "manifest.version"
}

// inspectMentorField runs fail-closed cognitive firewall, invisible/homoglyph smuggling detection,
// and secret quarantine against a single mentor capsule field.
func inspectMentorField(fieldName, value string) error {
	if value == "" {
		return nil
	}

	// 1. Reject invisible zero-width, bidi-override, and Unicode tag smuggling fail-closed.
	if bad, r := hasInvisibleOrBidiRune(value); bad {
		return fmt.Errorf("%w: invisible/bidi Unicode rune U+%04X detected in %s. Remediation: strip zero-width and directional control characters before importing",
			ErrMentorFirewallBlocked, r, fieldName)
	}

	// 2. NFKC + Homoglyph skeleton scan via Coppermind cognitive firewall.
	folded := foldHomoglyphs(value)
	for _, candidate := range []string{value, folded} {
		fw, err := security.InspectCognitiveThreats(candidate)
		if err != nil {
			return fmt.Errorf("%w: cognitive threat inspection error on %s: %v", ErrMentorFirewallBlocked, fieldName, err)
		}
		if fw.IsCritical || fw.TaintScore > 0 || len(fw.Flags) > 0 {
			return fmt.Errorf("%w: OWASP LLM01 injection pattern %v detected in %s. Remediation: remove imperative directives or system delimiters from mentor card text",
				ErrMentorFirewallBlocked, fw.Flags, fieldName)
		}
		for _, pat := range mentorExtraHijackPatterns {
			if pat.Regex.MatchString(candidate) {
				return fmt.Errorf("%w: %s detected in %s. Remediation: mentor cards must contain advisory engineering guidance only",
					ErrMentorFirewallBlocked, pat.Name, fieldName)
			}
		}
	}

	// 3. Fail-closed secret & credential quarantine (raw keys, tokens, high-entropy secrets).
	// For pure lowercase kebab-case identifiers (e.g. "mcp-04-zero-background-authority"), still run
	// all credential regex patterns via a multi-token prefix so English slugs don't trip standalone
	// high-entropy heuristics while real secrets (sk-..., AKIA..., ghp_...) are still blocked.
	if isIdentifierField(fieldName) && kebabSlugRegex.MatchString(value) {
		secRes, err := security.SanitizeMemory("identifier " + value)
		if err != nil {
			return fmt.Errorf("%w: %v in %s. Remediation: replace raw credentials with placeholder variable names",
				ErrMentorSecretDetected, err, fieldName)
		}
		for _, dt := range secRes.DetectedTypes {
			if dt != "High-Entropy Secret" {
				return fmt.Errorf("%w: secret pattern %v detected in %s. Remediation: strip all API keys, tokens, and passwords before importing or exporting",
					ErrMentorSecretDetected, secRes.DetectedTypes, fieldName)
			}
		}
		return nil
	}

	secRes, err := security.SanitizeMemory(value)
	if err != nil {
		return fmt.Errorf("%w: %v in %s. Remediation: replace raw credentials with placeholder variable names (e.g. locksmith run)",
			ErrMentorSecretDetected, err, fieldName)
	}
	if secRes.RedactedCount > 0 {
		return fmt.Errorf("%w: secret pattern %v detected in %s. Remediation: strip all API keys, tokens, and passwords before importing or exporting",
			ErrMentorSecretDetected, secRes.DetectedTypes, fieldName)
	}

	return nil
}

func validateAuthorityTierLock(tier, location string) error {
	trimmed := strings.TrimSpace(tier)
	if trimmed == "" || strings.EqualFold(trimmed, TierMentorCapsule) {
		return nil
	}
	return fmt.Errorf("%w: %s attempted to claim authority tier %q (only %s is permitted). Remediation: remove higher epistemic tier claims from the mentor capsule",
		ErrMentorTierEscalation, location, trimmed, TierMentorCapsule)
}

// ValidateMentorManifest validates schema bounds, epistemic tier lock, cognitive firewall,
// and secret quarantine for all fields of a MentorCapsuleManifest.
func ValidateMentorManifest(m *MentorCapsuleManifest) error {
	if m == nil {
		return fmt.Errorf("%w: manifest is nil", ErrMentorValidation)
	}
	if strings.TrimSpace(m.SchemaVersion) != MentorSchemaVersion {
		return fmt.Errorf("%w: unsupported schema_version %q (expected %q). Remediation: upgrade capsule schema to %s",
			ErrMentorValidation, m.SchemaVersion, MentorSchemaVersion, MentorSchemaVersion)
	}
	if strings.TrimSpace(m.Name) == "" {
		return fmt.Errorf("%w: capsule name is required", ErrMentorValidation)
	}
	if strings.TrimSpace(m.Version) == "" {
		return fmt.Errorf("%w: capsule version is required", ErrMentorValidation)
	}
	if strings.TrimSpace(m.Author) == "" {
		return fmt.Errorf("%w: capsule author is required", ErrMentorValidation)
	}
	if err := validateAuthorityTierLock(m.AuthorityTier, "manifest"); err != nil {
		return err
	}
	if len(m.Cards) == 0 {
		return fmt.Errorf("%w: capsule must contain at least 1 mentor card", ErrMentorValidation)
	}
	if len(m.Cards) > MaxMentorCardsPerCapsule {
		return fmt.Errorf("%w: capsule contains %d cards (max %d). Remediation: split large packs into focused domain capsules",
			ErrMentorValidation, len(m.Cards), MaxMentorCardsPerCapsule)
	}

	// Scan manifest metadata fields
	for field, val := range map[string]string{
		"manifest.name":    m.Name,
		"manifest.version": m.Version,
		"manifest.author":  m.Author,
	} {
		if err := inspectMentorField(field, val); err != nil {
			return err
		}
	}

	seenIDs := make(map[string]struct{}, len(m.Cards))
	for i, card := range m.Cards {
		prefix := fmt.Sprintf("cards[%d](%s)", i, card.ID)
		if strings.TrimSpace(card.ID) == "" {
			return fmt.Errorf("%w: cards[%d] missing required id", ErrMentorValidation, i)
		}
		if _, dup := seenIDs[card.ID]; dup {
			return fmt.Errorf("%w: duplicate card id %q", ErrMentorValidation, card.ID)
		}
		seenIDs[card.ID] = struct{}{}

		if err := validateAuthorityTierLock(card.AuthorityTier, prefix); err != nil {
			return err
		}
		if strings.TrimSpace(card.Domain) == "" {
			return fmt.Errorf("%w: %s missing required domain", ErrMentorValidation, prefix)
		}
		if strings.TrimSpace(card.Title) == "" {
			return fmt.Errorf("%w: %s missing required title", ErrMentorValidation, prefix)
		}
		if utf8.RuneCountInString(card.Title) > MaxMentorTitleLen {
			return fmt.Errorf("%w: %s title exceeds %d chars (%d)", ErrMentorValidation, prefix, MaxMentorTitleLen, utf8.RuneCountInString(card.Title))
		}
		if len(card.Triggers) == 0 {
			return fmt.Errorf("%w: %s must define at least 1 trigger", ErrMentorValidation, prefix)
		}
		if len(card.Triggers) > MaxMentorTriggersPerCard {
			return fmt.Errorf("%w: %s defines %d triggers (max %d)", ErrMentorValidation, prefix, len(card.Triggers), MaxMentorTriggersPerCard)
		}
		if strings.TrimSpace(card.SecureDefault) == "" {
			return fmt.Errorf("%w: %s missing required secure_default", ErrMentorValidation, prefix)
		}
		if utf8.RuneCountInString(card.SecureDefault) > MaxMentorSecureDefaultLen {
			return fmt.Errorf("%w: %s secure_default exceeds %d chars (%d). Remediation: keep secure_default concise (<= %d chars) to prevent context bloat",
				ErrMentorValidation, prefix, MaxMentorSecureDefaultLen, utf8.RuneCountInString(card.SecureDefault), MaxMentorSecureDefaultLen)
		}
		if strings.TrimSpace(card.WhyOneLiner) == "" {
			return fmt.Errorf("%w: %s missing required why_one_liner", ErrMentorValidation, prefix)
		}
		if utf8.RuneCountInString(card.WhyOneLiner) > MaxMentorWhyOneLinerLen {
			return fmt.Errorf("%w: %s why_one_liner exceeds %d chars (%d). Remediation: explain why in one concise sentence (<= %d chars)",
				ErrMentorValidation, prefix, MaxMentorWhyOneLinerLen, utf8.RuneCountInString(card.WhyOneLiner), MaxMentorWhyOneLinerLen)
		}
		if utf8.RuneCountInString(card.DeterministicEq) > MaxMentorAnalogyLen {
			return fmt.Errorf("%w: %s deterministic_analogy exceeds %d chars (%d)", ErrMentorValidation, prefix, MaxMentorAnalogyLen, utf8.RuneCountInString(card.DeterministicEq))
		}
		if utf8.RuneCountInString(card.CodeSnippet) > MaxMentorCodeSnippetLen {
			return fmt.Errorf("%w: %s code_snippet exceeds %d chars (%d)", ErrMentorValidation, prefix, MaxMentorCodeSnippetLen, utf8.RuneCountInString(card.CodeSnippet))
		}

		// Inspect every card text field through the cognitive firewall & secret scanner
		fields := []struct {
			name string
			val  string
		}{
			{prefix + ".id", card.ID},
			{prefix + ".domain", card.Domain},
			{prefix + ".title", card.Title},
			{prefix + ".deterministic_analogy", card.DeterministicEq},
			{prefix + ".secure_default", card.SecureDefault},
			{prefix + ".why_one_liner", card.WhyOneLiner},
			{prefix + ".code_snippet", card.CodeSnippet},
			{prefix + ".kata_ref", card.KataRef},
			{prefix + ".cwe_or_owasp", card.CWEOrOWASP},
		}
		for _, f := range fields {
			if err := inspectMentorField(f.name, f.val); err != nil {
				return err
			}
		}
		for j, trig := range card.Triggers {
			if err := inspectMentorField(fmt.Sprintf("%s.triggers[%d]", prefix, j), trig); err != nil {
				return err
			}
		}
	}

	return nil
}

// VerifyMentorManifest executes the full Two-Gate Import Quarantine:
// Gate 1: Schema validation, epistemic tier lock, Merkle root verification, and Ed25519 signature check.
// Gate 2: Cognitive firewall (NFKC + homoglyphs + OWASP LLM01) and secret quarantine on every card field.
// Returns the assigned provenance tag (TRUST_SIGNED_CAPSULE or TAINT_UNVERIFIED_DRAFT).
func VerifyMentorManifest(m *MentorCapsuleManifest, opts MentorImportOptions) (string, error) {
	if err := ValidateMentorManifest(m); err != nil {
		return "", err
	}

	expectedRoot := ComputeMerkleRoot(m.Cards)
	if strings.TrimSpace(m.MerkleRoot) == "" || !strings.EqualFold(strings.TrimSpace(m.MerkleRoot), expectedRoot) {
		return "", fmt.Errorf("%w: expected merkle_root %s, got %q. Remediation: re-compute and re-sign the capsule manifest from trusted source",
			ErrMentorMerkleMismatch, expectedRoot, m.MerkleRoot)
	}

	hasSig := strings.TrimSpace(m.Signature) != ""
	if !hasSig {
		if len(opts.RequiredPubKey) == ed25519.PublicKeySize {
			return "", fmt.Errorf("%w: capsule %q is unsigned, but a verified Ed25519 public key is required. Remediation: sign the capsule or omit --pubkey with --allow-unsigned for local drafts",
				ErrMentorUnsigned, m.Name)
		}
		if !opts.AllowUnsigned {
			return "", fmt.Errorf("%w: capsule %q has no Ed25519 signature. Remediation: pass --allow-unsigned to import as %s, or verify a signed release",
				ErrMentorUnsigned, m.Name, ProvenanceUnverifiedDraft)
		}
		m.AuthorityTier = TierMentorCapsule
		return ProvenanceUnverifiedDraft, nil
	}

	sigBytes, err := hex.DecodeString(strings.TrimSpace(m.Signature))
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return "", fmt.Errorf("%w: malformed hex Ed25519 signature. Remediation: re-sign capsule with a valid Ed25519 key", ErrMentorSignatureFailed)
	}

	var pubKey ed25519.PublicKey
	if len(opts.RequiredPubKey) == ed25519.PublicKeySize {
		pubKey = opts.RequiredPubKey
	} else if strings.TrimSpace(m.PublicKey) != "" {
		decodedPub, decErr := hex.DecodeString(strings.TrimSpace(m.PublicKey))
		if decErr != nil || len(decodedPub) != ed25519.PublicKeySize {
			return "", fmt.Errorf("%w: malformed embedded public_key", ErrMentorSignatureFailed)
		}
		pubKey = ed25519.PublicKey(decodedPub)
	} else {
		return "", fmt.Errorf("%w: signature present without required or embedded public key. Remediation: supply --pubkey <hex>", ErrMentorSignatureFailed)
	}

	if !ed25519.Verify(pubKey, []byte(expectedRoot), sigBytes) {
		return "", fmt.Errorf("%w: Ed25519 signature does not match merkle_root %s. Remediation: reject tampered archive and re-fetch from authoritative source",
			ErrMentorSignatureFailed, expectedRoot)
	}

	m.AuthorityTier = TierMentorCapsule
	return ProvenanceVerifiedSigned, nil
}

// SignMentorManifest validates, hard-locks TIER_2_MENTOR_CAPSULE, computes MerkleRoot,
// and attaches a detached Ed25519 signature over MerkleRoot.
func SignMentorManifest(m *MentorCapsuleManifest, privKey ed25519.PrivateKey) error {
	if m == nil {
		return fmt.Errorf("%w: manifest is nil", ErrMentorValidation)
	}
	if m.SchemaVersion == "" {
		m.SchemaVersion = MentorSchemaVersion
	}
	if m.CreatedAt.IsZero() {
		m.CreatedAt = time.Now().UTC()
	}
	if err := ValidateMentorManifest(m); err != nil {
		return err
	}
	m.AuthorityTier = TierMentorCapsule
	for i := range m.Cards {
		m.Cards[i].AuthorityTier = ""
	}
	m.MerkleRoot = ComputeMerkleRoot(m.Cards)

	if len(privKey) == ed25519.PrivateKeySize {
		sig := ed25519.Sign(privKey, []byte(m.MerkleRoot))
		m.Signature = hex.EncodeToString(sig)
		pub := privKey.Public().(ed25519.PublicKey)
		m.PublicKey = hex.EncodeToString(pub)
	}
	return nil
}

// checkRawJSONTierEscalation inspects raw JSON keys on the manifest and card objects
// to block authority escalation attempts using alternate field names (e.g. "tier", "epistemic_tier").
func checkRawJSONTierEscalation(raw []byte) error {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return fmt.Errorf("%w: malformed JSON manifest: %v", ErrMentorValidation, err)
	}

	tierKeys := []string{"tier", "authority_tier", "epistemic_tier", "trust_tier"}
	checkMap := func(obj map[string]json.RawMessage, loc string) error {
		for _, k := range tierKeys {
			if rawVal, ok := obj[k]; ok {
				var s string
				if err := json.Unmarshal(rawVal, &s); err == nil {
					if err := validateAuthorityTierLock(s, loc+"."+k); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}

	if err := checkMap(top, "manifest"); err != nil {
		return err
	}
	if rawCards, ok := top["cards"]; ok {
		var cardMaps []map[string]json.RawMessage
		if err := json.Unmarshal(rawCards, &cardMaps); err == nil {
			for i, cm := range cardMaps {
				if err := checkMap(cm, fmt.Sprintf("cards[%d]", i)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// ReadMentorCapsule reads and parses a MentorCapsuleManifest from either a raw JSON stream
// or a gzipped tar/JSON archive (.capsule), enforcing a strict 5MB zip-bomb guard via io.LimitReader.
func ReadMentorCapsule(r io.Reader) (*MentorCapsuleManifest, error) {
	// Bound compressed/raw input stream first
	boundedIn := io.LimitReader(r, MaxMentorCapsuleBytes+1)
	br := bufio.NewReader(boundedIn)

	magic, err := br.Peek(2)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("%w: failed to read capsule stream: %v", ErrMentorValidation, err)
	}

	var manifestJSON []byte

	if len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		// Gzip stream: wrap decompressor in io.LimitReader to defeat zip bombs with bounded memory.
		gr, err := gzip.NewReader(br)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid gzip mentor capsule: %v", ErrMentorValidation, err)
		}
		defer gr.Close()

		decompressed, err := io.ReadAll(io.LimitReader(gr, MaxMentorCapsuleBytes+1))
		if err != nil {
			return nil, fmt.Errorf("%w: failed decompressing mentor capsule: %v", ErrMentorValidation, err)
		}
		if len(decompressed) > MaxMentorCapsuleBytes {
			return nil, fmt.Errorf("%w: decompressed payload exceeds %d bytes (zip-bomb guard triggered). Remediation: keep mentor capsules under 5MB",
				ErrMentorCapsuleTooLarge, MaxMentorCapsuleBytes)
		}

		trimmed := bytes.TrimSpace(decompressed)
		if len(trimmed) > 0 && trimmed[0] == '{' {
			manifestJSON = trimmed
		} else {
			// Parse as tar archive with strict zip-slip & entry-type defenses
			tr := tar.NewReader(bytes.NewReader(decompressed))
			var totalRead int64
			for {
				hdr, err := tr.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					return nil, fmt.Errorf("%w: corrupted tar archive in mentor capsule: %v", ErrMentorValidation, err)
				}

				cleanName := filepath.Clean(hdr.Name)
				if strings.HasPrefix(cleanName, "..") || filepath.IsAbs(cleanName) || strings.Contains(cleanName, string(filepath.Separator)+"..") {
					return nil, fmt.Errorf("%w: illegal path %q in mentor capsule", ErrMentorZipSlip, hdr.Name)
				}
				if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA && hdr.Typeflag != tar.TypeDir {
					return nil, fmt.Errorf("%w: disallowed archive entry type %q for %q", ErrMentorZipSlip, hdr.Typeflag, hdr.Name)
				}
				if hdr.Typeflag == tar.TypeDir {
					continue
				}

				remaining := int64(MaxMentorCapsuleBytes+1) - totalRead
				if remaining <= 0 {
					return nil, fmt.Errorf("%w: archive contents exceed %d bytes", ErrMentorCapsuleTooLarge, MaxMentorCapsuleBytes)
				}
				entryData, err := io.ReadAll(io.LimitReader(tr, remaining))
				if err != nil {
					return nil, fmt.Errorf("%w: error reading tar entry %q: %v", ErrMentorValidation, hdr.Name, err)
				}
				totalRead += int64(len(entryData))
				if totalRead > MaxMentorCapsuleBytes {
					return nil, fmt.Errorf("%w: archive contents exceed %d bytes", ErrMentorCapsuleTooLarge, MaxMentorCapsuleBytes)
				}

				if cleanName == "mentor_manifest.json" || cleanName == "manifest.json" {
					manifestJSON = entryData
				}
			}
			if len(manifestJSON) == 0 {
				return nil, fmt.Errorf("%w: tar capsule missing mentor_manifest.json", ErrMentorValidation)
			}
		}
	} else {
		raw, err := io.ReadAll(br)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to read mentor capsule JSON: %v", ErrMentorValidation, err)
		}
		if len(raw) > MaxMentorCapsuleBytes {
			return nil, fmt.Errorf("%w: payload exceeds %d bytes", ErrMentorCapsuleTooLarge, MaxMentorCapsuleBytes)
		}
		manifestJSON = raw
	}

	if err := checkRawJSONTierEscalation(manifestJSON); err != nil {
		return nil, err
	}

	var manifest MentorCapsuleManifest
	if err := json.Unmarshal(manifestJSON, &manifest); err != nil {
		return nil, fmt.Errorf("%w: invalid mentor manifest JSON: %v", ErrMentorValidation, err)
	}
	return &manifest, nil
}

// ReadMentorCapsuleFile opens and reads a mentor capsule (.mentor.json or .capsule) with bounded size guards.
func ReadMentorCapsuleFile(path string) (*MentorCapsuleManifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open mentor capsule %q: %w", path, err)
	}
	defer f.Close()
	return ReadMentorCapsule(f)
}

// ExportMentorCapsule validates, scans for leaked secrets/injections (fail-closed), optionally signs,
// and writes a tar.gz `.capsule` archive containing `mentor_manifest.json`.
func ExportMentorCapsule(m *MentorCapsuleManifest, outputPath string, privKey ed25519.PrivateKey) error {
	if err := SignMentorManifest(m, privKey); err != nil {
		return err
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if len(data) > MaxMentorCapsuleBytes {
		return fmt.Errorf("%w: serialized manifest exceeds %d bytes", ErrMentorCapsuleTooLarge, MaxMentorCapsuleBytes)
	}

	if err := os.MkdirAll(filepath.Dir(outputPath), 0700); err != nil {
		return err
	}
	tmpPath := outputPath + ".tmp"
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}

	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)
	if err := writeTarEntry(tw, "mentor_manifest.json", data); err != nil {
		_ = tw.Close()
		_ = gw.Close()
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tw.Close(); err != nil {
		_ = gw.Close()
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := gw.Close(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, outputPath)
}

// ExportMentorCapsuleJSON validates, scans for leaked secrets/injections (fail-closed), optionally signs,
// and writes a canonical `.mentor.json` manifest file.
func ExportMentorCapsuleJSON(m *MentorCapsuleManifest, outputPath string, privKey ed25519.PrivateKey) error {
	if err := SignMentorManifest(m, privKey); err != nil {
		return err
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if len(data) > MaxMentorCapsuleBytes {
		return fmt.Errorf("%w: serialized manifest exceeds %d bytes", ErrMentorCapsuleTooLarge, MaxMentorCapsuleBytes)
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0700); err != nil {
		return err
	}
	return os.WriteFile(outputPath, append(data, '\n'), 0644)
}

// ImportMentorCapsuleToStore parses, verifies (fail-closed), embeds, and persists a mentor capsule
// into SQLite's isolated `mentor_capsules` and `mentor_cards` tables via the single-writer channel.
func ImportMentorCapsuleToStore(ctx context.Context, store SQLiteAccessor, r io.Reader, opts MentorImportOptions) (*ImportedMentorCapsule, error) {
	if store == nil {
		return nil, fmt.Errorf("mentor capsule import requires a local SQLite store")
	}
	manifest, err := ReadMentorCapsule(r)
	if err != nil {
		return nil, err
	}
	return PersistVerifiedMentorManifest(ctx, store, manifest, opts)
}

// ImportMentorCapsuleFileToStore imports a mentor capsule file (.mentor.json or .capsule) into SQLite.
func ImportMentorCapsuleFileToStore(ctx context.Context, store SQLiteAccessor, path string, opts MentorImportOptions) (*ImportedMentorCapsule, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open mentor capsule %q: %w", path, err)
	}
	defer f.Close()
	return ImportMentorCapsuleToStore(ctx, store, f, opts)
}

// PersistVerifiedMentorManifest runs VerifyMentorManifest and persists the verified cards
// atomically through SQLite's single-writer transaction ring.
func PersistVerifiedMentorManifest(ctx context.Context, store SQLiteAccessor, manifest *MentorCapsuleManifest, opts MentorImportOptions) (*ImportedMentorCapsule, error) {
	if store == nil {
		return nil, fmt.Errorf("mentor capsule import requires a local SQLite store")
	}

	provenance, err := VerifyMentorManifest(manifest, opts)
	if err != nil {
		return nil, err
	}

	embedder := embedding.NewLocalHashEmbedder(128)
	cardVectors := make([][]byte, len(manifest.Cards))
	for i, card := range manifest.Cards {
		embedText := strings.Join([]string{
			card.Domain,
			card.Title,
			strings.Join(card.Triggers, " "),
			card.DeterministicEq,
			card.SecureDefault,
			card.WhyOneLiner,
			card.CWEOrOWASP,
		}, " ")
		vec, err := embedder.Embed(ctx, embedText)
		if err != nil {
			return nil, fmt.Errorf("failed to embed mentor card %q: %w", card.ID, err)
		}
		cardVectors[i] = encodeFloat32Vector(vec)
	}

	importedAt := time.Now().UTC()
	merklePrefix := manifest.MerkleRoot
	if len(merklePrefix) > 12 {
		merklePrefix = merklePrefix[:12]
	}

	err = store.RunWriteTx(ctx, func(tx *sql.Tx) error {
		// Replace existing capsule cards atomically
		if _, err := tx.Exec(`DELETE FROM mentor_cards WHERE capsule_name = ?`, manifest.Name); err != nil {
			return err
		}
		_, err := tx.Exec(`
			INSERT INTO mentor_capsules (
				name, version, schema_version, author, created_at, imported_at,
				authority_tier, provenance, merkle_root, signature, public_key, card_count
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(name) DO UPDATE SET
				version=excluded.version,
				schema_version=excluded.schema_version,
				author=excluded.author,
				created_at=excluded.created_at,
				imported_at=excluded.imported_at,
				authority_tier=excluded.authority_tier,
				provenance=excluded.provenance,
				merkle_root=excluded.merkle_root,
				signature=excluded.signature,
				public_key=excluded.public_key,
				card_count=excluded.card_count
		`,
			manifest.Name,
			manifest.Version,
			manifest.SchemaVersion,
			manifest.Author,
			manifest.CreatedAt.UTC().UnixNano(),
			importedAt.UnixNano(),
			TierMentorCapsule,
			provenance,
			manifest.MerkleRoot,
			manifest.Signature,
			manifest.PublicKey,
			len(manifest.Cards),
		)
		if err != nil {
			return err
		}

		for i, card := range manifest.Cards {
			triggersJSON, _ := json.Marshal(card.Triggers)
			_, err := tx.Exec(`
				INSERT INTO mentor_cards (
					id, capsule_name, capsule_version, capsule_merkle_prefix,
					domain, triggers_json, title, deterministic_analogy,
					secure_default, why_one_liner, code_snippet, kata_ref,
					cwe_or_owasp, authority_tier, provenance, vector_blob
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT(id) DO UPDATE SET
					capsule_name=excluded.capsule_name,
					capsule_version=excluded.capsule_version,
					capsule_merkle_prefix=excluded.capsule_merkle_prefix,
					domain=excluded.domain,
					triggers_json=excluded.triggers_json,
					title=excluded.title,
					deterministic_analogy=excluded.deterministic_analogy,
					secure_default=excluded.secure_default,
					why_one_liner=excluded.why_one_liner,
					code_snippet=excluded.code_snippet,
					kata_ref=excluded.kata_ref,
					cwe_or_owasp=excluded.cwe_or_owasp,
					authority_tier=excluded.authority_tier,
					provenance=excluded.provenance,
					vector_blob=excluded.vector_blob
			`,
				card.ID,
				manifest.Name,
				manifest.Version,
				merklePrefix,
				card.Domain,
				string(triggersJSON),
				card.Title,
				card.DeterministicEq,
				card.SecureDefault,
				card.WhyOneLiner,
				card.CodeSnippet,
				card.KataRef,
				card.CWEOrOWASP,
				TierMentorCapsule,
				provenance,
				cardVectors[i],
			)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to persist mentor capsule: %w", err)
	}

	mentorWriteGen.Add(1)

	return &ImportedMentorCapsule{
		Name:          manifest.Name,
		Version:       manifest.Version,
		SchemaVersion: manifest.SchemaVersion,
		Author:        manifest.Author,
		CreatedAt:     manifest.CreatedAt.UTC(),
		ImportedAt:    importedAt,
		AuthorityTier: TierMentorCapsule,
		Provenance:    provenance,
		MerkleRoot:    manifest.MerkleRoot,
		CardCount:     len(manifest.Cards),
	}, nil
}

// ListMentorCapsules retrieves all imported mentor capsules via a lock-free WAL read.
func ListMentorCapsules(ctx context.Context, store SQLiteAccessor) ([]ImportedMentorCapsule, error) {
	if store == nil {
		return nil, nil
	}
	rows, err := store.DB().QueryContext(ctx, `
		SELECT name, version, schema_version, author, created_at, imported_at,
		       authority_tier, provenance, merkle_root, card_count
		FROM mentor_capsules
		ORDER BY name ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []ImportedMentorCapsule
	for rows.Next() {
		var (
			rec                  ImportedMentorCapsule
			createdAt, importedAt int64
		)
		if err := rows.Scan(
			&rec.Name, &rec.Version, &rec.SchemaVersion, &rec.Author,
			&createdAt, &importedAt, &rec.AuthorityTier, &rec.Provenance,
			&rec.MerkleRoot, &rec.CardCount,
		); err != nil {
			return nil, err
		}
		rec.CreatedAt = time.Unix(0, createdAt).UTC()
		rec.ImportedAt = time.Unix(0, importedAt).UTC()
		result = append(result, rec)
	}
	return result, rows.Err()
}

// LoadAllMentorCards loads all stored mentor cards lock-free from SQLite WAL.
func LoadAllMentorCards(ctx context.Context, store SQLiteAccessor) ([]MentorCardRecord, error) {
	if store == nil {
		return nil, nil
	}
	rows, err := store.DB().QueryContext(ctx, `
		SELECT id, capsule_name, capsule_version, capsule_merkle_prefix,
		       domain, triggers_json, title, deterministic_analogy,
		       secure_default, why_one_liner, code_snippet, kata_ref,
		       cwe_or_owasp, authority_tier, provenance, vector_blob
		FROM mentor_cards
		ORDER BY id ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []MentorCardRecord
	for rows.Next() {
		var (
			rec          MentorCardRecord
			triggersJSON string
			vecBlob      []byte
		)
		if err := rows.Scan(
			&rec.Card.ID, &rec.CapsuleName, &rec.CapsuleVersion, &rec.MerklePrefix,
			&rec.Card.Domain, &triggersJSON, &rec.Card.Title, &rec.Card.DeterministicEq,
			&rec.Card.SecureDefault, &rec.Card.WhyOneLiner, &rec.Card.CodeSnippet, &rec.Card.KataRef,
			&rec.Card.CWEOrOWASP, &rec.AuthorityTier, &rec.Provenance, &vecBlob,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(triggersJSON), &rec.Card.Triggers)
		rec.Card.AuthorityTier = rec.AuthorityTier
		rec.Vector = decodeFloat32Vector(vecBlob)
		records = append(records, rec)
	}
	return records, rows.Err()
}

// GetMentorCapsuleManifestFromStore reconstructs a MentorCapsuleManifest from SQLite for export.
func GetMentorCapsuleManifestFromStore(ctx context.Context, store SQLiteAccessor, name string) (*MentorCapsuleManifest, error) {
	if store == nil {
		return nil, fmt.Errorf("mentor capsule export requires a local SQLite store")
	}
	var (
		m         MentorCapsuleManifest
		createdAt int64
	)
	err := store.DB().QueryRowContext(ctx, `
		SELECT schema_version, name, version, author, created_at, authority_tier, merkle_root, signature, public_key
		FROM mentor_capsules
		WHERE name = ?
	`, name).Scan(
		&m.SchemaVersion, &m.Name, &m.Version, &m.Author, &createdAt,
		&m.AuthorityTier, &m.MerkleRoot, &m.Signature, &m.PublicKey,
	)
	if err != nil {
		return nil, fmt.Errorf("mentor capsule %q not found: %w", name, err)
	}
	m.CreatedAt = time.Unix(0, createdAt).UTC()

	rows, err := store.DB().QueryContext(ctx, `
		SELECT id, domain, triggers_json, title, deterministic_analogy,
		       secure_default, why_one_liner, code_snippet, kata_ref, cwe_or_owasp
		FROM mentor_cards
		WHERE capsule_name = ?
		ORDER BY id ASC
	`, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var (
			c            MentorCard
			triggersJSON string
		)
		if err := rows.Scan(
			&c.ID, &c.Domain, &triggersJSON, &c.Title, &c.DeterministicEq,
			&c.SecureDefault, &c.WhyOneLiner, &c.CodeSnippet, &c.KataRef, &c.CWEOrOWASP,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(triggersJSON), &c.Triggers)
		m.Cards = append(m.Cards, c)
	}
	return &m, rows.Err()
}

func encodeFloat32Vector(vec []float32) []byte {
	if len(vec) == 0 {
		return nil
	}
	buf := make([]byte, len(vec)*4)
	for i, v := range vec {
		binary.LittleEndian.PutUint32(buf[i*4:(i+1)*4], math.Float32bits(v))
	}
	return buf
}

func decodeFloat32Vector(b []byte) []float32 {
	if len(b) == 0 || len(b)%4 != 0 {
		return nil
	}
	n := len(b) / 4
	vec := make([]float32, n)
	for i := 0; i < n; i++ {
		vec[i] = math.Float32frombits(binary.LittleEndian.Uint32(b[i*4 : (i+1)*4]))
	}
	return vec
}

var (
	defaultMentorOnce      sync.Once
	defaultMentorManifests []*MentorCapsuleManifest
	defaultMentorRecords   []MentorCardRecord
	defaultMentorErr       error
)

// DefaultMentorManifests returns the 3 verified built-in v1.0 Security Mentor Capsule manifests
// (18 curated cards total) embedded in the binary for zero-config out-of-the-box ideation recall.
func DefaultMentorManifests() ([]*MentorCapsuleManifest, error) {
	defaultMentorOnce.Do(func() {
		payloads := capsules.DefaultMentorCapsulePayloads()
		manifests := make([]*MentorCapsuleManifest, 0, len(payloads))
		records := make([]MentorCardRecord, 0, 18)
		embedder := embedding.NewLocalHashEmbedder(128)

		for _, payload := range payloads {
			m, err := ReadMentorCapsule(bytes.NewReader(payload))
			if err != nil {
				defaultMentorErr = err
				return
			}
			if _, err := VerifyMentorManifest(m, MentorImportOptions{AllowUnsigned: true}); err != nil {
				defaultMentorErr = err
				return
			}
			manifests = append(manifests, m)

			merklePrefix := m.MerkleRoot
			if len(merklePrefix) > 12 {
				merklePrefix = merklePrefix[:12]
			}
			for _, card := range m.Cards {
				embedText := strings.Join([]string{
					card.Domain,
					card.Title,
					strings.Join(card.Triggers, " "),
					card.DeterministicEq,
					card.SecureDefault,
					card.WhyOneLiner,
					card.CWEOrOWASP,
				}, " ")
				vec, _ := embedder.Embed(context.Background(), embedText)
				cardCopy := card
				cardCopy.AuthorityTier = TierMentorCapsule
				records = append(records, MentorCardRecord{
					Card:           cardCopy,
					CapsuleName:    m.Name,
					CapsuleVersion: m.Version,
					MerklePrefix:   merklePrefix,
					AuthorityTier:  TierMentorCapsule,
					Provenance:     ProvenanceUnverifiedDraft,
					Vector:         vec,
				})
			}
		}

		defaultMentorManifests = manifests
		defaultMentorRecords = records
	})

	if defaultMentorErr != nil {
		return nil, defaultMentorErr
	}
	out := make([]*MentorCapsuleManifest, len(defaultMentorManifests))
	copy(out, defaultMentorManifests)
	return out, nil
}

// DefaultMentorCardRecords returns pre-embedded copies of all 18 built-in curated mentor cards
// so SQLiteMentorLens works zero-config on a brand-new workstation without manual import.
func DefaultMentorCardRecords() ([]MentorCardRecord, error) {
	if _, err := DefaultMentorManifests(); err != nil {
		return nil, err
	}
	out := make([]MentorCardRecord, len(defaultMentorRecords))
	copy(out, defaultMentorRecords)
	return out, nil
}
