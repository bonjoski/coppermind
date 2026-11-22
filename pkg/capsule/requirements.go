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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/bonjoski/coppermind/capsules"
	"github.com/bonjoski/coppermind/pkg/embedding"
	"golang.org/x/text/unicode/norm"
)

const (
	// RequirementsSchemaVersion is the canonical schema identifier for PO & Requirements capsules.
	RequirementsSchemaVersion = "bonjoski-requirements-v1"

	// MaxRequirementsStoryBytes is the strict 256KB DoS cap for --story-file and story inputs.
	MaxRequirementsStoryBytes = 256 * 1024

	// MaxRequirementsCriteria is the hard ceiling on criteria returned per story.
	MaxRequirementsCriteria = 3

	// MaxRequirementsTotalTokens is the hard token ceiling for default Markdown criteria output.
	MaxRequirementsTotalTokens = 180

	// Field & catalog bounds (anti-bloat / anti-DoS).
	MaxRequirementsCardsPerCapsule = 100
	MaxRequirementsKeywordsPerCard = 32
	MaxReqPlainTitleLen            = 120
	MaxReqGWTFieldLen              = 220
	MaxReqWhyLen                   = 220
	MaxReqVerifyCmdLen             = 200
)

// TriggerFlag maps cleanly to the 5-Question Plain-English Blast-Radius Card.
type TriggerFlag string

const (
	TriggerAuthDataMoney  TriggerFlag = "auth_data_money"   // Q1
	TriggerAIRAGContext   TriggerFlag = "ai_rag_context"    // Q2
	TriggerAIStateMutate  TriggerFlag = "ai_state_mutation" // Q3
	TriggerSupplyChainMCP TriggerFlag = "supply_chain_mcp"  // Q4
	TriggerSecretsPII     TriggerFlag = "secrets_pii"       // Q5
)

var validTriggerFlags = map[TriggerFlag]struct{}{
	TriggerAuthDataMoney:  {},
	TriggerAIRAGContext:   {},
	TriggerAIStateMutate:  {},
	TriggerSupplyChainMCP: {},
	TriggerSecretsPII:     {},
}

// allowedVerifyCmdVerbs enforces strict local bonjoski CLI allowlisting for verify_cmd.
var allowedVerifyCmdVerbs = map[string]struct{}{
	"aegisbox":   {},
	"argus":      {},
	"locksmith":  {},
	"bomhound":   {},
	"soulcaster": {},
	"fabrial":    {},
	"airlock":    {},
}

var (
	reqWriteGen atomic.Uint64

	ErrRequirementsValidation        = errors.New("requirements capsule validation failed")
	ErrRequirementsHTMLRejected      = errors.New("requirements capsule rejected unsafe HTML/XSS markup")
	ErrRequirementsVerifyCmdRejected = errors.New("requirements capsule rejected unauthorized or unsafe verify_cmd")
	ErrRequirementsMerkleMismatch    = errors.New("requirements capsule merkle root mismatch")
	ErrRequirementsSignatureFailed   = errors.New("requirements capsule Ed25519 signature verification failed")
	ErrRequirementsUnsigned          = errors.New("requirements capsule is unsigned")
	ErrRequirementsFirewallBlocked   = errors.New("requirements capsule blocked by cognitive firewall")
	ErrRequirementsSecretDetected    = errors.New("requirements capsule blocked by secret quarantine")
	ErrRequirementsTierEscalation    = errors.New("requirements capsule authority escalation rejected")
	ErrRequirementsStoryTooLarge     = errors.New("story input exceeds maximum 256KB size limit")
)

// AbuseCaseCriterion represents one sprint-ready Given/When/Then safety requirement.
type AbuseCaseCriterion struct {
	ID          string        `json:"id"`
	Triggers    []TriggerFlag `json:"triggers"`
	Keywords    []string      `json:"keywords"`
	PlainTitle  string        `json:"plain_title"`
	Given       string        `json:"given"`
	When        string        `json:"when"`
	Then        string        `json:"then"`
	WhyOneLiner string        `json:"why_one_liner"`
	VerifyCmd   string        `json:"verify_cmd"`
	KataRef     string        `json:"kata_ref,omitempty"`
}

// RequirementsCapsuleManifest wraps a versioned, verifiable collection of AbuseCaseCriteria.
type RequirementsCapsuleManifest struct {
	SchemaVersion string               `json:"schema_version"`
	Name          string               `json:"name"`
	Version       string               `json:"version"`
	Author        string               `json:"author"`
	CreatedAt     time.Time            `json:"created_at"`
	AuthorityTier string               `json:"authority_tier,omitempty"`
	MerkleRoot    string               `json:"merkle_root"`
	Signature     string               `json:"signature,omitempty"`
	PublicKey     string               `json:"public_key,omitempty"`
	Criteria      []AbuseCaseCriterion `json:"criteria"`
}

// RequirementsCriterionRecord is a stored requirement criterion joined with provenance and vector.
type RequirementsCriterionRecord struct {
	Criterion      AbuseCaseCriterion
	CapsuleName    string
	CapsuleVersion string
	MerklePrefix   string
	AuthorityTier  string
	Provenance     string
	Vector         []float32
}

// AllTriggerFlags returns the canonical ordered list of all 5-Q blast-radius trigger flags.
func AllTriggerFlags() []TriggerFlag {
	return []TriggerFlag{
		TriggerAuthDataMoney,
		TriggerAIRAGContext,
		TriggerAIStateMutate,
		TriggerSupplyChainMCP,
		TriggerSecretsPII,
	}
}

// ValidTriggerFlag returns true if flag is one of the 5 canonical blast-radius triggers.
func ValidTriggerFlag(flag TriggerFlag) bool {
	_, ok := validTriggerFlags[flag]
	return ok
}

// ParseTriggerFlags parses a comma-separated list of TriggerFlags, rejecting unknown values fail-closed.
func ParseTriggerFlags(csv string) ([]TriggerFlag, error) {
	trimmed := strings.TrimSpace(csv)
	if trimmed == "" {
		return nil, nil
	}
	parts := strings.Split(trimmed, ",")
	out := make([]TriggerFlag, 0, len(parts))
	seen := make(map[TriggerFlag]struct{}, len(parts))
	for _, p := range parts {
		f := TriggerFlag(strings.ToLower(strings.TrimSpace(p)))
		if f == "" {
			continue
		}
		if !ValidTriggerFlag(f) {
			return nil, fmt.Errorf("%w: unknown trigger flag %q (valid: auth_data_money, ai_rag_context, ai_state_mutation, supply_chain_mcp, secrets_pii)", ErrRequirementsValidation, p)
		}
		if _, dup := seen[f]; dup {
			continue
		}
		seen[f] = struct{}{}
		out = append(out, f)
	}
	return out, nil
}

// RequirementsWriteGeneration returns a monotonically increasing generation counter incremented
// after every requirements capsule write commit, enabling zero-hop-tax read caching.
func RequirementsWriteGeneration() uint64 {
	return reqWriteGen.Load()
}

var (
	ansiEscapeRegex = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]`)
	unsafeHTMLRegex = regexp.MustCompile(`(?i)(?:<\s*/?\s*(?:script|img|iframe|svg|object|embed|style|link|meta|form|input|button|body|head|html|base|applet|details|marquee|video|audio|source|a)\b|javascript\s*:|vbscript\s*:|data\s*:\s*text/html|\bon(?:error|load|click|mouseover|focus|blur|submit|input)\s*=)`)
	markdownXSSLink = regexp.MustCompile(`(?i)\]\s*\(\s*(?:javascript|vbscript|data)\s*:`)
)

// StripControlAndANSI strips ANSI escape sequences and non-printable ASCII/Unicode control characters.
func StripControlAndANSI(s string) string {
	noANSI := ansiEscapeRegex.ReplaceAllString(s, "")
	var sb strings.Builder
	sb.Grow(len(noANSI))
	for _, r := range noANSI {
		if r == '\t' {
			sb.WriteRune(' ')
			continue
		}
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || unicode.Is(unicode.Cc, r) {
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

// HasUnsafeHTMLOrXSS detects raw HTML tags (<script, <img, <iframe, etc.) and javascript: markdown XSS vectors.
func HasUnsafeHTMLOrXSS(s string) bool {
	if s == "" {
		return false
	}
	folded := foldHomoglyphs(s)
	for _, cand := range []string{s, folded} {
		if unsafeHTMLRegex.MatchString(cand) || markdownXSSLink.MatchString(cand) {
			return true
		}
	}
	return false
}

// ValidateVerifyCmd strictly validates that verify_cmd begins ONLY with a sanctioned bonjoski
// CLI verb and contains zero shell chaining, piping, substitution, or redirection metacharacters.
func ValidateVerifyCmd(cmd string) error {
	if bad, r := hasInvisibleOrBidiRune(cmd); bad {
		return fmt.Errorf("%w: invisible/bidi rune U+%04X in verify_cmd", ErrRequirementsVerifyCmdRejected, r)
	}
	if ansiEscapeRegex.MatchString(cmd) {
		return fmt.Errorf("%w: ANSI escape sequence detected in verify_cmd", ErrRequirementsVerifyCmdRejected)
	}
	for _, r := range cmd {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: control character 0x%02X detected in verify_cmd", ErrRequirementsVerifyCmdRejected, r)
		}
	}

	normalized := norm.NFKC.String(cmd)
	trimmed := strings.TrimSpace(normalized)
	if trimmed == "" {
		return fmt.Errorf("%w: verify_cmd is required", ErrRequirementsVerifyCmdRejected)
	}
	if utf8.RuneCountInString(trimmed) > MaxReqVerifyCmdLen {
		return fmt.Errorf("%w: verify_cmd exceeds %d chars", ErrRequirementsVerifyCmdRejected, MaxReqVerifyCmdLen)
	}
	if HasUnsafeHTMLOrXSS(trimmed) {
		return fmt.Errorf("%w: HTML/XSS pattern detected in verify_cmd", ErrRequirementsHTMLRejected)
	}

	// Reject any shell chaining, piping, substitution, or redirection metacharacters.
	forbiddenSubstrings := []string{";", "|", "&&", "&", "`", "$(", "${", ">", "<", "\n", "\r"}
	for _, bad := range forbiddenSubstrings {
		if strings.Contains(trimmed, bad) {
			return fmt.Errorf("%w: forbidden shell metacharacter %q in verify_cmd %q", ErrRequirementsVerifyCmdRejected, bad, trimmed)
		}
	}

	fields := strings.Fields(trimmed)
	if len(fields) == 0 {
		return fmt.Errorf("%w: empty verify_cmd", ErrRequirementsVerifyCmdRejected)
	}
	verb := fields[0]
	if _, ok := allowedVerifyCmdVerbs[verb]; !ok {
		return fmt.Errorf("%w: verify_cmd verb %q is not in allowlist (allowed: aegisbox, argus, locksmith, bomhound, soulcaster, fabrial, airlock)", ErrRequirementsVerifyCmdRejected, verb)
	}

	return nil
}

// ComputeRequirementsMerkleRoot computes a deterministic SHA-256 binary Merkle root over criteria sorted by ID.
func ComputeRequirementsMerkleRoot(criteria []AbuseCaseCriterion) string {
	if len(criteria) == 0 {
		sum := sha256.Sum256(nil)
		return hex.EncodeToString(sum[:])
	}

	sorted := make([]AbuseCaseCriterion, len(criteria))
	copy(sorted, criteria)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].ID < sorted[j].ID
	})

	level := make([][32]byte, len(sorted))
	for i, c := range sorted {
		trigs := make([]TriggerFlag, len(c.Triggers))
		copy(trigs, c.Triggers)
		kws := make([]string, len(c.Keywords))
		copy(kws, c.Keywords)
		canon := AbuseCaseCriterion{
			ID:          c.ID,
			Triggers:    trigs,
			Keywords:    kws,
			PlainTitle:  c.PlainTitle,
			Given:       c.Given,
			When:        c.When,
			Then:        c.Then,
			WhyOneLiner: c.WhyOneLiner,
			VerifyCmd:   c.VerifyCmd,
			KataRef:     c.KataRef,
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

func inspectRequirementsField(fieldName, value string) error {
	if value == "" {
		return nil
	}
	if HasUnsafeHTMLOrXSS(value) {
		return fmt.Errorf("%w: unsafe HTML/XSS markup detected in %s", ErrRequirementsHTMLRejected, fieldName)
	}
	if ansiEscapeRegex.MatchString(value) {
		return fmt.Errorf("%w: ANSI escape sequence detected in %s", ErrRequirementsValidation, fieldName)
	}
	for _, r := range value {
		if (r < 0x20 && r != '\t') || r == 0x7f {
			return fmt.Errorf("%w: control character 0x%02X detected in %s", ErrRequirementsValidation, r, fieldName)
		}
	}
	if err := inspectMentorField(fieldName, value); err != nil {
		if errors.Is(err, ErrMentorFirewallBlocked) {
			return fmt.Errorf("%w: %v", ErrRequirementsFirewallBlocked, err)
		}
		if errors.Is(err, ErrMentorSecretDetected) {
			return fmt.Errorf("%w: %v", ErrRequirementsSecretDetected, err)
		}
		return fmt.Errorf("%w: %v", ErrRequirementsValidation, err)
	}
	return nil
}

// ValidateRequirementsManifest validates schema bounds, authority tier lock, HTML/XSS defense,
// cognitive firewall, secret quarantine, and verify_cmd allowlisting for a RequirementsCapsuleManifest.
func ValidateRequirementsManifest(m *RequirementsCapsuleManifest) error {
	if m == nil {
		return fmt.Errorf("%w: manifest is nil", ErrRequirementsValidation)
	}
	if strings.TrimSpace(m.SchemaVersion) != RequirementsSchemaVersion {
		return fmt.Errorf("%w: unsupported schema_version %q (expected %q)", ErrRequirementsValidation, m.SchemaVersion, RequirementsSchemaVersion)
	}
	if strings.TrimSpace(m.Name) == "" {
		return fmt.Errorf("%w: capsule name is required", ErrRequirementsValidation)
	}
	if strings.TrimSpace(m.Version) == "" {
		return fmt.Errorf("%w: capsule version is required", ErrRequirementsValidation)
	}
	if strings.TrimSpace(m.Author) == "" {
		return fmt.Errorf("%w: capsule author is required", ErrRequirementsValidation)
	}
	if err := validateAuthorityTierLock(m.AuthorityTier, "manifest"); err != nil {
		return fmt.Errorf("%w: %v", ErrRequirementsTierEscalation, err)
	}
	if len(m.Criteria) == 0 {
		return fmt.Errorf("%w: capsule must contain at least 1 criterion", ErrRequirementsValidation)
	}
	if len(m.Criteria) > MaxRequirementsCardsPerCapsule {
		return fmt.Errorf("%w: capsule contains %d criteria (max %d)", ErrRequirementsValidation, len(m.Criteria), MaxRequirementsCardsPerCapsule)
	}

	for field, val := range map[string]string{
		"manifest.name":    m.Name,
		"manifest.version": m.Version,
		"manifest.author":  m.Author,
	} {
		if err := inspectRequirementsField(field, val); err != nil {
			return err
		}
	}

	seenIDs := make(map[string]struct{}, len(m.Criteria))
	for i, c := range m.Criteria {
		prefix := fmt.Sprintf("criteria[%d](%s)", i, c.ID)
		if strings.TrimSpace(c.ID) == "" {
			return fmt.Errorf("%w: criteria[%d] missing required id", ErrRequirementsValidation, i)
		}
		if _, dup := seenIDs[c.ID]; dup {
			return fmt.Errorf("%w: duplicate criterion id %q", ErrRequirementsValidation, c.ID)
		}
		seenIDs[c.ID] = struct{}{}

		if len(c.Triggers) == 0 {
			return fmt.Errorf("%w: %s must define at least 1 trigger flag", ErrRequirementsValidation, prefix)
		}
		for _, trig := range c.Triggers {
			if !ValidTriggerFlag(trig) {
				return fmt.Errorf("%w: %s has invalid trigger flag %q", ErrRequirementsValidation, prefix, trig)
			}
		}
		if len(c.Keywords) == 0 {
			return fmt.Errorf("%w: %s must define at least 1 keyword", ErrRequirementsValidation, prefix)
		}
		if len(c.Keywords) > MaxRequirementsKeywordsPerCard {
			return fmt.Errorf("%w: %s defines %d keywords (max %d)", ErrRequirementsValidation, prefix, len(c.Keywords), MaxRequirementsKeywordsPerCard)
		}

		if strings.TrimSpace(c.PlainTitle) == "" || utf8.RuneCountInString(c.PlainTitle) > MaxReqPlainTitleLen {
			return fmt.Errorf("%w: %s plain_title must be 1..%d chars", ErrRequirementsValidation, prefix, MaxReqPlainTitleLen)
		}
		if strings.TrimSpace(c.Given) == "" || utf8.RuneCountInString(c.Given) > MaxReqGWTFieldLen {
			return fmt.Errorf("%w: %s given must be 1..%d chars", ErrRequirementsValidation, prefix, MaxReqGWTFieldLen)
		}
		if strings.TrimSpace(c.When) == "" || utf8.RuneCountInString(c.When) > MaxReqGWTFieldLen {
			return fmt.Errorf("%w: %s when must be 1..%d chars", ErrRequirementsValidation, prefix, MaxReqGWTFieldLen)
		}
		if strings.TrimSpace(c.Then) == "" || utf8.RuneCountInString(c.Then) > MaxReqGWTFieldLen {
			return fmt.Errorf("%w: %s then must be 1..%d chars", ErrRequirementsValidation, prefix, MaxReqGWTFieldLen)
		}
		if strings.TrimSpace(c.WhyOneLiner) == "" || utf8.RuneCountInString(c.WhyOneLiner) > MaxReqWhyLen {
			return fmt.Errorf("%w: %s why_one_liner must be 1..%d chars", ErrRequirementsValidation, prefix, MaxReqWhyLen)
		}

		if err := ValidateVerifyCmd(c.VerifyCmd); err != nil {
			return fmt.Errorf("%s: %w", prefix, err)
		}

		fields := []struct {
			name string
			val  string
		}{
			{prefix + ".id", c.ID},
			{prefix + ".plain_title", c.PlainTitle},
			{prefix + ".given", c.Given},
			{prefix + ".when", c.When},
			{prefix + ".then", c.Then},
			{prefix + ".why_one_liner", c.WhyOneLiner},
			{prefix + ".verify_cmd", c.VerifyCmd},
			{prefix + ".kata_ref", c.KataRef},
		}
		for _, f := range fields {
			if err := inspectRequirementsField(f.name, f.val); err != nil {
				return err
			}
		}
		for j, kw := range c.Keywords {
			if err := inspectRequirementsField(fmt.Sprintf("%s.keywords[%d]", prefix, j), kw); err != nil {
				return err
			}
		}
	}

	return nil
}

// VerifyRequirementsManifest runs the two-gate import quarantine over a RequirementsCapsuleManifest.
func VerifyRequirementsManifest(m *RequirementsCapsuleManifest, opts MentorImportOptions) (string, error) {
	if err := ValidateRequirementsManifest(m); err != nil {
		return "", err
	}

	expectedRoot := ComputeRequirementsMerkleRoot(m.Criteria)
	if strings.TrimSpace(m.MerkleRoot) == "" || !strings.EqualFold(strings.TrimSpace(m.MerkleRoot), expectedRoot) {
		return "", fmt.Errorf("%w: expected merkle_root %s, got %q", ErrRequirementsMerkleMismatch, expectedRoot, m.MerkleRoot)
	}

	hasSig := strings.TrimSpace(m.Signature) != ""
	if !hasSig {
		if len(opts.RequiredPubKey) == ed25519.PublicKeySize {
			return "", fmt.Errorf("%w: capsule %q is unsigned, but a verified Ed25519 public key is required", ErrRequirementsUnsigned, m.Name)
		}
		if !opts.AllowUnsigned {
			return "", fmt.Errorf("%w: capsule %q has no Ed25519 signature (pass --allow-unsigned for local drafts)", ErrRequirementsUnsigned, m.Name)
		}
		m.AuthorityTier = TierMentorCapsule
		return ProvenanceUnverifiedDraft, nil
	}

	sigBytes, err := hex.DecodeString(strings.TrimSpace(m.Signature))
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return "", fmt.Errorf("%w: malformed hex Ed25519 signature", ErrRequirementsSignatureFailed)
	}

	var pubKey ed25519.PublicKey
	if len(opts.RequiredPubKey) == ed25519.PublicKeySize {
		pubKey = opts.RequiredPubKey
	} else if strings.TrimSpace(m.PublicKey) != "" {
		decodedPub, decErr := hex.DecodeString(strings.TrimSpace(m.PublicKey))
		if decErr != nil || len(decodedPub) != ed25519.PublicKeySize {
			return "", fmt.Errorf("%w: malformed embedded public_key", ErrRequirementsSignatureFailed)
		}
		pubKey = ed25519.PublicKey(decodedPub)
	} else {
		return "", fmt.Errorf("%w: signature present without required or embedded public key", ErrRequirementsSignatureFailed)
	}

	if !ed25519.Verify(pubKey, []byte(expectedRoot), sigBytes) {
		return "", fmt.Errorf("%w: Ed25519 signature does not match merkle_root %s", ErrRequirementsSignatureFailed, expectedRoot)
	}

	m.AuthorityTier = TierMentorCapsule
	return ProvenanceVerifiedSigned, nil
}

// SignRequirementsManifest validates, hard-locks TIER_2_MENTOR_CAPSULE, computes MerkleRoot,
// and optionally attaches an Ed25519 signature.
func SignRequirementsManifest(m *RequirementsCapsuleManifest, privKey ed25519.PrivateKey) error {
	if m == nil {
		return fmt.Errorf("%w: manifest is nil", ErrRequirementsValidation)
	}
	if m.SchemaVersion == "" {
		m.SchemaVersion = RequirementsSchemaVersion
	}
	if m.CreatedAt.IsZero() {
		m.CreatedAt = time.Now().UTC()
	}
	if err := ValidateRequirementsManifest(m); err != nil {
		return err
	}
	m.AuthorityTier = TierMentorCapsule
	m.MerkleRoot = ComputeRequirementsMerkleRoot(m.Criteria)
	if len(privKey) == ed25519.PrivateKeySize {
		sig := ed25519.Sign(privKey, []byte(m.MerkleRoot))
		m.Signature = hex.EncodeToString(sig)
		pub := privKey.Public().(ed25519.PublicKey)
		m.PublicKey = hex.EncodeToString(pub)
	}
	return nil
}

// ReadRequirementsCapsule reads a RequirementsCapsuleManifest from raw JSON, gzip-compressed JSON,
// or a gzipped tar archive (.capsule) containing requirements_manifest.json or manifest.json,
// enforcing a strict 5MB zip-bomb guard, Zip-Slip defenses, and raw JSON tier-escalation checks.
func ReadRequirementsCapsule(r io.Reader) (*RequirementsCapsuleManifest, error) {
	boundedIn := io.LimitReader(r, MaxMentorCapsuleBytes+1)
	br := bufio.NewReader(boundedIn)

	magic, err := br.Peek(2)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("%w: failed reading capsule stream: %v", ErrRequirementsValidation, err)
	}

	var raw []byte
	if len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gr, err := gzip.NewReader(br)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid gzip requirements capsule: %v", ErrRequirementsValidation, err)
		}
		defer gr.Close()
		decompressed, err := io.ReadAll(io.LimitReader(gr, MaxMentorCapsuleBytes+1))
		if err != nil {
			return nil, fmt.Errorf("%w: failed decompressing requirements capsule: %v", ErrRequirementsValidation, err)
		}
		if len(decompressed) > MaxMentorCapsuleBytes {
			return nil, fmt.Errorf("%w: decompressed payload exceeds %d bytes", ErrMentorCapsuleTooLarge, MaxMentorCapsuleBytes)
		}

		trimmed := bytes.TrimSpace(decompressed)
		if len(trimmed) > 0 && trimmed[0] == '{' {
			raw = trimmed
		} else {
			tr := tar.NewReader(bytes.NewReader(decompressed))
			var totalRead int64
			for {
				hdr, err := tr.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					return nil, fmt.Errorf("%w: corrupted tar archive in requirements capsule: %v", ErrRequirementsValidation, err)
				}

				cleanName := filepath.Clean(hdr.Name)
				if strings.HasPrefix(cleanName, "..") || filepath.IsAbs(cleanName) || strings.Contains(cleanName, string(filepath.Separator)+"..") {
					return nil, fmt.Errorf("%w: illegal path %q in requirements capsule", ErrMentorZipSlip, hdr.Name)
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
					return nil, fmt.Errorf("%w: error reading tar entry %q: %v", ErrRequirementsValidation, hdr.Name, err)
				}
				totalRead += int64(len(entryData))
				if totalRead > MaxMentorCapsuleBytes {
					return nil, fmt.Errorf("%w: archive contents exceed %d bytes", ErrMentorCapsuleTooLarge, MaxMentorCapsuleBytes)
				}

				if cleanName == "requirements_manifest.json" || cleanName == "manifest.json" || cleanName == "mentor_manifest.json" {
					raw = entryData
				}
			}
			if len(raw) == 0 {
				return nil, fmt.Errorf("%w: tar capsule missing requirements_manifest.json", ErrRequirementsValidation)
			}
		}
	} else {
		raw, err = io.ReadAll(br)
		if err != nil {
			return nil, fmt.Errorf("%w: failed reading requirements capsule: %v", ErrRequirementsValidation, err)
		}
		if len(raw) > MaxMentorCapsuleBytes {
			return nil, fmt.Errorf("%w: payload exceeds %d bytes", ErrMentorCapsuleTooLarge, MaxMentorCapsuleBytes)
		}
	}

	if err := checkRawJSONTierEscalation(raw); err != nil {
		if errors.Is(err, ErrMentorTierEscalation) {
			return nil, fmt.Errorf("%w: %v", ErrRequirementsTierEscalation, err)
		}
		return nil, fmt.Errorf("%w: %v", ErrRequirementsValidation, err)
	}

	var manifest RequirementsCapsuleManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%w: invalid requirements manifest JSON: %v", ErrRequirementsValidation, err)
	}
	return &manifest, nil
}

// ExportRequirementsCapsule validates, scans for secrets/XSS/injections (fail-closed), optionally signs,
// and atomically writes a tar.gz `.capsule` archive containing `requirements_manifest.json`.
func ExportRequirementsCapsule(m *RequirementsCapsuleManifest, outputPath string, privKey ed25519.PrivateKey) error {
	if err := SignRequirementsManifest(m, privKey); err != nil {
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
	if err := writeTarEntry(tw, "requirements_manifest.json", data); err != nil {
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

// ExportRequirementsCapsuleJSON validates, scans (fail-closed), optionally signs,
// and writes a canonical requirements JSON manifest file.
func ExportRequirementsCapsuleJSON(m *RequirementsCapsuleManifest, outputPath string, privKey ed25519.PrivateKey) error {
	if err := SignRequirementsManifest(m, privKey); err != nil {
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

// ReadRequirementsCapsuleFile opens and reads a requirements capsule JSON or .capsule file with size guards.
func ReadRequirementsCapsuleFile(path string) (*RequirementsCapsuleManifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open requirements capsule %q: %w", path, err)
	}
	defer f.Close()
	return ReadRequirementsCapsule(f)
}

// DetectCapsuleSchema peeks a capsule file (raw JSON, gzipped JSON, or tar.gz .capsule archive)
// and returns its schema_version string if present.
func DetectCapsuleSchema(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	br := bufio.NewReader(io.LimitReader(f, MaxMentorCapsuleBytes))
	magic, err := br.Peek(2)
	if err != nil && err != io.EOF {
		return ""
	}

	var data []byte
	if len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gr, gzErr := gzip.NewReader(br)
		if gzErr != nil {
			return ""
		}
		defer gr.Close()
		decompressed, readErr := io.ReadAll(io.LimitReader(gr, MaxMentorCapsuleBytes))
		if readErr != nil {
			return ""
		}
		trimmed := bytes.TrimSpace(decompressed)
		if len(trimmed) > 0 && trimmed[0] == '{' {
			data = trimmed
		} else {
			tr := tar.NewReader(bytes.NewReader(decompressed))
			for {
				hdr, tErr := tr.Next()
				if tErr != nil {
					break
				}
				cleanName := filepath.Clean(hdr.Name)
				if cleanName == "requirements_manifest.json" || cleanName == "mentor_manifest.json" || cleanName == "manifest.json" {
					entryData, eErr := io.ReadAll(io.LimitReader(tr, 64*1024))
					if eErr == nil {
						data = entryData
					}
					break
				}
			}
		}
	} else {
		data, err = io.ReadAll(io.LimitReader(br, 64*1024))
		if err != nil {
			return ""
		}
	}

	var hdr struct {
		SchemaVersion string `json:"schema_version"`
	}
	if err := json.Unmarshal(data, &hdr); err == nil && strings.TrimSpace(hdr.SchemaVersion) != "" {
		return strings.TrimSpace(hdr.SchemaVersion)
	}
	// Fallback quick scan if file > 64KB or partial JSON
	if idx := strings.Index(string(data), `"schema_version"`); idx >= 0 {
		sub := string(data)[idx:]
		if strings.Contains(sub, RequirementsSchemaVersion) {
			return RequirementsSchemaVersion
		}
		if strings.Contains(sub, MentorSchemaVersion) {
			return MentorSchemaVersion
		}
	}
	return ""
}

// ImportRequirementsCapsuleToStore parses, verifies (fail-closed), embeds, and persists a requirements capsule
// into SQLite's WAL tables via the single-writer ring.
func ImportRequirementsCapsuleToStore(ctx context.Context, store SQLiteAccessor, r io.Reader, opts MentorImportOptions) (*ImportedMentorCapsule, error) {
	if store == nil {
		return nil, fmt.Errorf("requirements capsule import requires a local SQLite store")
	}
	manifest, err := ReadRequirementsCapsule(r)
	if err != nil {
		return nil, err
	}
	return PersistVerifiedRequirementsManifest(ctx, store, manifest, opts)
}

// ImportRequirementsCapsuleFileToStore imports a requirements capsule file into SQLite.
func ImportRequirementsCapsuleFileToStore(ctx context.Context, store SQLiteAccessor, path string, opts MentorImportOptions) (*ImportedMentorCapsule, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open requirements capsule %q: %w", path, err)
	}
	defer f.Close()
	return ImportRequirementsCapsuleToStore(ctx, store, f, opts)
}

// PersistVerifiedRequirementsManifest verifies and persists a RequirementsCapsuleManifest into SQLite WAL.
func PersistVerifiedRequirementsManifest(ctx context.Context, store SQLiteAccessor, manifest *RequirementsCapsuleManifest, opts MentorImportOptions) (*ImportedMentorCapsule, error) {
	if store == nil {
		return nil, fmt.Errorf("requirements capsule import requires a local SQLite store")
	}
	provenance, err := VerifyRequirementsManifest(manifest, opts)
	if err != nil {
		return nil, err
	}

	embedder := embedding.NewLocalHashEmbedder(128)
	vectors := make([][]byte, len(manifest.Criteria))
	for i, c := range manifest.Criteria {
		trigStrs := make([]string, len(c.Triggers))
		for j, t := range c.Triggers {
			trigStrs[j] = string(t)
		}
		embedText := strings.Join([]string{
			strings.Join(trigStrs, " "),
			strings.Join(c.Keywords, " "),
			c.PlainTitle,
			c.Given,
			c.When,
			c.Then,
			c.WhyOneLiner,
		}, " ")
		vec, err := embedder.Embed(ctx, embedText)
		if err != nil {
			return nil, fmt.Errorf("failed to embed criterion %q: %w", c.ID, err)
		}
		vectors[i] = encodeFloat32Vector(vec)
	}

	importedAt := time.Now().UTC()
	merklePrefix := manifest.MerkleRoot
	if len(merklePrefix) > 12 {
		merklePrefix = merklePrefix[:12]
	}

	err = store.RunWriteTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.Exec(`DELETE FROM requirements_criteria WHERE capsule_name = ?`, manifest.Name); err != nil {
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
			len(manifest.Criteria),
		)
		if err != nil {
			return err
		}

		for i, c := range manifest.Criteria {
			triggersJSON, _ := json.Marshal(c.Triggers)
			keywordsJSON, _ := json.Marshal(c.Keywords)
			_, err := tx.Exec(`
				INSERT INTO requirements_criteria (
					id, capsule_name, capsule_version, capsule_merkle_prefix,
					triggers_json, keywords_json, plain_title, given_clause,
					when_clause, then_clause, why_one_liner, verify_cmd,
					kata_ref, authority_tier, provenance, vector_blob
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT(id) DO UPDATE SET
					capsule_name=excluded.capsule_name,
					capsule_version=excluded.capsule_version,
					capsule_merkle_prefix=excluded.capsule_merkle_prefix,
					triggers_json=excluded.triggers_json,
					keywords_json=excluded.keywords_json,
					plain_title=excluded.plain_title,
					given_clause=excluded.given_clause,
					when_clause=excluded.when_clause,
					then_clause=excluded.then_clause,
					why_one_liner=excluded.why_one_liner,
					verify_cmd=excluded.verify_cmd,
					kata_ref=excluded.kata_ref,
					authority_tier=excluded.authority_tier,
					provenance=excluded.provenance,
					vector_blob=excluded.vector_blob
			`,
				c.ID,
				manifest.Name,
				manifest.Version,
				merklePrefix,
				string(triggersJSON),
				string(keywordsJSON),
				c.PlainTitle,
				c.Given,
				c.When,
				c.Then,
				c.WhyOneLiner,
				c.VerifyCmd,
				c.KataRef,
				TierMentorCapsule,
				provenance,
				vectors[i],
			)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to persist requirements capsule: %w", err)
	}

	reqWriteGen.Add(1)

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
		CardCount:     len(manifest.Criteria),
	}, nil
}

// LoadAllRequirementsCriteria loads all imported requirements criteria lock-free from SQLite WAL.
func LoadAllRequirementsCriteria(ctx context.Context, store SQLiteAccessor) ([]RequirementsCriterionRecord, error) {
	if store == nil {
		return nil, nil
	}
	rows, err := store.DB().QueryContext(ctx, `
		SELECT id, capsule_name, capsule_version, capsule_merkle_prefix,
		       triggers_json, keywords_json, plain_title, given_clause,
		       when_clause, then_clause, why_one_liner, verify_cmd,
		       kata_ref, authority_tier, provenance, vector_blob
		FROM requirements_criteria
		ORDER BY id ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []RequirementsCriterionRecord
	for rows.Next() {
		var (
			rec          RequirementsCriterionRecord
			triggersJSON string
			keywordsJSON string
			vecBlob      []byte
		)
		if err := rows.Scan(
			&rec.Criterion.ID, &rec.CapsuleName, &rec.CapsuleVersion, &rec.MerklePrefix,
			&triggersJSON, &keywordsJSON, &rec.Criterion.PlainTitle, &rec.Criterion.Given,
			&rec.Criterion.When, &rec.Criterion.Then, &rec.Criterion.WhyOneLiner, &rec.Criterion.VerifyCmd,
			&rec.Criterion.KataRef, &rec.AuthorityTier, &rec.Provenance, &vecBlob,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(triggersJSON), &rec.Criterion.Triggers)
		_ = json.Unmarshal([]byte(keywordsJSON), &rec.Criterion.Keywords)
		rec.Vector = decodeFloat32Vector(vecBlob)
		records = append(records, rec)
	}
	return records, rows.Err()
}

// ReadStoryBounded reads story/PRD text with a strict 256KB io.LimitReader cap (anti-DoS).
func ReadStoryBounded(r io.Reader) (string, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxRequirementsStoryBytes+1))
	if err != nil {
		return "", fmt.Errorf("failed reading story input: %w", err)
	}
	if len(data) > MaxRequirementsStoryBytes {
		return "", fmt.Errorf("%w: story input exceeds %d bytes", ErrRequirementsStoryTooLarge, MaxRequirementsStoryBytes)
	}
	return string(data), nil
}

// ReadStoryFileBounded opens and reads a local PRD/story file enforcing the strict 256KB cap.
func ReadStoryFileBounded(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("failed opening story file %q: %w", path, err)
	}
	defer f.Close()
	return ReadStoryBounded(f)
}

var (
	defaultReqOnce     sync.Once
	defaultReqManifest *RequirementsCapsuleManifest
	defaultReqRecords  []RequirementsCriterionRecord
	defaultReqErr      error
)

// DefaultRequirementsManifest returns the verified built-in 10-card PO & Requirements starter pack.
func DefaultRequirementsManifest() (*RequirementsCapsuleManifest, error) {
	defaultReqOnce.Do(func() {
		m, err := ReadRequirementsCapsule(bytes.NewReader(capsules.DefaultPOAbuseCaseCriteriaJSON))
		if err != nil {
			defaultReqErr = err
			return
		}
		if _, err := VerifyRequirementsManifest(m, MentorImportOptions{AllowUnsigned: true}); err != nil {
			defaultReqErr = err
			return
		}
		defaultReqManifest = m

		embedder := embedding.NewLocalHashEmbedder(128)
		merklePrefix := m.MerkleRoot
		if len(merklePrefix) > 12 {
			merklePrefix = merklePrefix[:12]
		}
		recs := make([]RequirementsCriterionRecord, len(m.Criteria))
		for i, c := range m.Criteria {
			trigStrs := make([]string, len(c.Triggers))
			for j, t := range c.Triggers {
				trigStrs[j] = string(t)
			}
			embedText := strings.Join([]string{
				strings.Join(trigStrs, " "),
				strings.Join(c.Keywords, " "),
				c.PlainTitle,
				c.Given,
				c.When,
				c.Then,
				c.WhyOneLiner,
			}, " ")
			vec, _ := embedder.Embed(context.Background(), embedText)
			recs[i] = RequirementsCriterionRecord{
				Criterion:      c,
				CapsuleName:    m.Name,
				CapsuleVersion: m.Version,
				MerklePrefix:   merklePrefix,
				AuthorityTier:  TierMentorCapsule,
				Provenance:     ProvenanceUnverifiedDraft,
				Vector:         vec,
			}
		}
		defaultReqRecords = recs
	})
	if defaultReqErr != nil {
		return nil, defaultReqErr
	}
	return defaultReqManifest, nil
}

// DefaultRequirementsRecords returns pre-embedded built-in curated criteria records for zero-config lookup.
func DefaultRequirementsRecords() ([]RequirementsCriterionRecord, error) {
	if _, err := DefaultRequirementsManifest(); err != nil {
		return nil, err
	}
	out := make([]RequirementsCriterionRecord, len(defaultReqRecords))
	copy(out, defaultReqRecords)
	return out, nil
}
