package mcp

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/bonjoski/coppermind/pkg/gitscope"
)

// BLPR-v1 DSSE / in-toto Statement v1 constants (RFC-2026-11-22-49).
const (
	StatementTypeV1 = "https://in-toto.io/Statement/v1"
	PredicateTypeV1 = "https://bonjoski.dev/attestation/paved-road/v1"
	DSSEPayloadType = "application/vnd.in-toto+json"
	BLPRSchemaVer   = "1.0.0"

	CoppermindServerVersion = "0.1.0"
)

var (
	// ErrReceiptPolicyDeny indicates a fail-closed BLPR-v1 receipt policy violation (e.g., symlinked receipt dir).
	ErrReceiptPolicyDeny = errors.New("receipt policy denied")
	// ErrReceiptDirSymlink indicates FABRIAL_RECEIPT_DIR or an ancestor is a symlink.
	ErrReceiptDirSymlink = fmt.Errorf("%w: refusing symlinked FABRIAL_RECEIPT_DIR", ErrReceiptPolicyDeny)

	blprSessionRe = regexp.MustCompile(`^sess_[0-9A-Za-z]+$`)
	blprHeadSHARe = regexp.MustCompile(`^[a-f0-9]{7,64}$`)
	blprKeyIDRe   = regexp.MustCompile(`^spiffe://bonjoski\.local/session/sess_[0-9A-Za-z]+$`)
)

// Verdict defines the BLPR-v1 evaluation verdict.
type Verdict string

const (
	VerdictAllow Verdict = "allow"
	VerdictDeny  Verdict = "deny"
	VerdictWarn  Verdict = "warn"
)

// ReceiptSubject identifies the hashed artifact covered by a BLPR-v1 receipt.
type ReceiptSubject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// ReceiptSessionLineage captures session correlation for a BLPR-v1 receipt.
type ReceiptSessionLineage struct {
	SessionID       string `json:"session_id"`
	ParentSessionID string `json:"parent_session_id,omitempty"`
	ActorMode       string `json:"actor_mode"`
	WorktreeHeadSHA string `json:"worktree_head_sha"`
}

// ReceiptProducer identifies the emitting tool and lifecycle stage.
type ReceiptProducer struct {
	Tool    string `json:"tool"`
	Version string `json:"version"`
	Stage   string `json:"stage"`
}

// ReceiptPredicate conforms to blpr-v1.schema.json ($defs.statement.properties.predicate).
type ReceiptPredicate struct {
	SchemaVersion  string                `json:"schema_version"`
	ReceiptID      string                `json:"receipt_id"`
	Timestamp      time.Time             `json:"timestamp"`
	Session        ReceiptSessionLineage `json:"session"`
	Producer       ReceiptProducer       `json:"producer"`
	Verdict        Verdict               `json:"verdict"`
	Proven         bool                  `json:"proven"`
	Claims         map[string]any        `json:"claims"`
	ParentReceipts []string              `json:"parent_receipts,omitempty"`
	FixForwardCode string                `json:"fix_forward_code,omitempty"`
}

// InTotoStatement represents an in-toto Statement v1 carrying a BLPR-v1 predicate.
type InTotoStatement struct {
	Type          string           `json:"_type"`
	Subject       []ReceiptSubject `json:"subject"`
	PredicateType string           `json:"predicateType"`
	Predicate     ReceiptPredicate `json:"predicate"`
}

// DSSESignature represents one DSSE envelope signature.
type DSSESignature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// DSSEEnvelope conforms to the DSSE specification and blpr-v1.schema.json.
type DSSEEnvelope struct {
	PayloadType string          `json:"payloadType"`
	Payload     string          `json:"payload"`
	Signatures  []DSSESignature `json:"signatures"`
}

// PAE computes the DSSE Pre-Authentication Encoding per spec:
// "DSSEv1 " + len(type) + " " + type + " " + len(body) + " " + body
func PAE(payloadType string, payload []byte) []byte {
	prefix := fmt.Sprintf("DSSEv1 %d %s %d ", len(payloadType), payloadType, len(payload))
	out := make([]byte, 0, len(prefix)+len(payload))
	out = append(out, prefix...)
	out = append(out, payload...)
	return out
}

// VerifyEnvelope verifies a DSSEEnvelope against the supplied Ed25519 public key and decodes the BLPR-v1 statement.
func VerifyEnvelope(env *DSSEEnvelope, pub ed25519.PublicKey) (*InTotoStatement, error) {
	if env == nil || env.PayloadType != DSSEPayloadType || len(env.Signatures) == 0 {
		return nil, errors.New("invalid or unsigned DSSE receipt envelope")
	}
	raw, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	pae := PAE(env.PayloadType, raw)
	verified := false
	for _, s := range env.Signatures {
		sigBytes, err := base64.StdEncoding.DecodeString(s.Sig)
		if err != nil || len(sigBytes) != ed25519.SignatureSize {
			continue
		}
		if ed25519.Verify(pub, pae, sigBytes) {
			verified = true
			break
		}
	}
	if !verified {
		return nil, errors.New("DSSE signature verification failed")
	}
	var stmt InTotoStatement
	if err := json.Unmarshal(raw, &stmt); err != nil {
		return nil, fmt.Errorf("unmarshal statement: %w", err)
	}
	if stmt.Type != StatementTypeV1 || stmt.PredicateType != PredicateTypeV1 {
		return nil, errors.New("unexpected in-toto statement or predicate type")
	}
	return &stmt, nil
}

// IdeationReceiptInput specifies parameters for emitting a Coppermind ideation BLPR-v1 receipt.
type IdeationReceiptInput struct {
	SessionID            string
	ParentSessionID      string
	ConjoinerSIRID       string
	Lens                 string
	Query                string
	ResultsCount         int
	OpenHighObservations int
}

// EmittedReceipt summarizes a persisted BLPR-v1 receipt.
type EmittedReceipt struct {
	ReceiptID string `json:"receipt_id"`
	FilePath  string `json:"receipt_path"`
	SessionID string `json:"session_id"`
	Signed    bool   `json:"signed"`
}

// EmitIdeationReceipt atomically writes a BLPR-v1 DSSE / in-toto Statement v1 receipt
// under FABRIAL_RECEIPT_DIR using os.OpenRoot (O_NOFOLLOW, 0600) and signs via
// LOCKSMITH_SOCKET action "sign_dsse" when reachable.
// Returns (nil, nil) if FABRIAL_RECEIPT_DIR is unset.
func EmitIdeationReceipt(ctx context.Context, in IdeationReceiptInput) (*EmittedReceipt, error) {
	receiptDir := strings.TrimSpace(os.Getenv("FABRIAL_RECEIPT_DIR"))
	if receiptDir == "" {
		return nil, nil
	}

	cleanDir, err := validateReceiptDir(receiptDir)
	if err != nil {
		return nil, err
	}

	sessionID := normalizeSessionID(in.SessionID)
	if sessionID == "" {
		sessionID = normalizeSessionID(os.Getenv("FABRIAL_SESSION_ID"))
	}
	if sessionID == "" {
		sessionID = generatePrefixedID("sess_")
	}

	parentSess := normalizeSessionID(in.ParentSessionID)
	if parentSess == "" {
		parentSess = normalizeSessionID(os.Getenv("FABRIAL_PARENT_SESSION_ID"))
	}

	lensName := strings.TrimSpace(strings.ToLower(in.Lens))
	if lensName == "" {
		lensName = "hybrid"
	}

	headSHA := resolveWorktreeHeadSHA()
	receiptID := generatePrefixedID("rcpt_")

	// Hash the ideation query + lens + result count without leaking raw PII into the receipt.
	subjHash := sha256.Sum256([]byte(fmt.Sprintf("coppermind:ideation:%s:%d:%s", lensName, in.ResultsCount, in.Query)))
	subject := ReceiptSubject{
		Name:   fmt.Sprintf("coppermind:%s", lensName),
		Digest: map[string]string{"sha256": hex.EncodeToString(subjHash[:])},
	}

	verdict := VerdictAllow
	if in.OpenHighObservations > 0 {
		verdict = VerdictWarn
	}

	claims := map[string]any{
		"lens":                   lensName,
		"results_count":          in.ResultsCount,
		"open_high_observations": in.OpenHighObservations,
	}

	sirID := strings.TrimSpace(in.ConjoinerSIRID)
	if sirID == "" {
		sirID = strings.TrimSpace(os.Getenv("CONJOINER_SIR_ID"))
	}
	var parentReceipts []string
	if sirID != "" {
		claims["conjoiner_sir_id"] = SanitizeSingleLine(sirID)
		if normalizedSIR := normalizeReceiptID(sirID); normalizedSIR != "" {
			parentReceipts = append(parentReceipts, normalizedSIR)
		}
	}

	stmt := InTotoStatement{
		Type:          StatementTypeV1,
		Subject:       []ReceiptSubject{subject},
		PredicateType: PredicateTypeV1,
		Predicate: ReceiptPredicate{
			SchemaVersion: BLPRSchemaVer,
			ReceiptID:     receiptID,
			Timestamp:     time.Now().UTC(),
			Session: ReceiptSessionLineage{
				SessionID:       sessionID,
				ParentSessionID: parentSess,
				ActorMode:       "aidlc",
				WorktreeHeadSHA: headSHA,
			},
			Producer: ReceiptProducer{
				Tool:    CoppermindToolName,
				Version: CoppermindServerVersion,
				Stage:   "ideation",
			},
			Verdict:        verdict,
			Proven:         false,
			Claims:         claims,
			ParentReceipts: parentReceipts,
		},
	}

	// Attempt amortized DSSE signing via LOCKSMITH_SOCKET when reachable.
	env, signed, err := buildAndSignEnvelope(ctx, &stmt)
	if err != nil {
		return nil, err
	}

	rawEnvelope, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("marshal BLPR-v1 envelope: %w", err)
	}
	rawEnvelope = append(rawEnvelope, '\n')

	finalName := fmt.Sprintf("%d-coppermind-%s.dsse.json", time.Now().UTC().UnixMilli(), strings.TrimPrefix(receiptID, "rcpt_"))
	if err := writeAtomicReceipt(cleanDir, finalName, rawEnvelope); err != nil {
		return nil, err
	}

	return &EmittedReceipt{
		ReceiptID: receiptID,
		FilePath:  filepath.Join(cleanDir, finalName),
		SessionID: sessionID,
		Signed:    signed,
	}, nil
}

func buildAndSignEnvelope(ctx context.Context, stmt *InTotoStatement) (*DSSEEnvelope, bool, error) {
	// First check whether Locksmith is reachable and can sign; if so, mark proven=true before marshaling.
	sockPath := resolveLocksmithSocket()
	if sockPath != "" {
		stmt.Predicate.Proven = true
		stmt.Predicate.Claims["signature_mode"] = "locksmith_dsse"
		payloadBytes, err := json.Marshal(stmt)
		if err != nil {
			return nil, false, fmt.Errorf("marshal BLPR-v1 statement: %w", err)
		}
		keyID, sigB64, signErr := signDSSEViaLocksmith(ctx, sockPath, stmt.Predicate.Session.SessionID, PAE(DSSEPayloadType, payloadBytes))
		if signErr == nil && sigB64 != "" {
			if !blprKeyIDRe.MatchString(keyID) {
				keyID = fmt.Sprintf("spiffe://bonjoski.local/session/%s", stmt.Predicate.Session.SessionID)
			}
			return &DSSEEnvelope{
				PayloadType: DSSEPayloadType,
				Payload:     base64.StdEncoding.EncodeToString(payloadBytes),
				Signatures: []DSSESignature{
					{KeyID: keyID, Sig: sigB64},
				},
			}, true, nil
		}
	}

	// Offline / unsigned local fallback when LOCKSMITH_SOCKET is unavailable.
	stmt.Predicate.Proven = false
	stmt.Predicate.Claims["signature_mode"] = "unsigned_local"
	payloadBytes, err := json.Marshal(stmt)
	if err != nil {
		return nil, false, fmt.Errorf("marshal BLPR-v1 statement: %w", err)
	}
	return &DSSEEnvelope{
		PayloadType: DSSEPayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payloadBytes),
		Signatures:  []DSSESignature{},
	}, false, nil
}

func resolveLocksmithSocket() string {
	if s := strings.TrimSpace(os.Getenv("LOCKSMITH_SOCKET")); s != "" {
		return s
	}
	if s := strings.TrimSpace(os.Getenv("LOCKSMITH_SOCK")); s != "" {
		return s
	}
	return ""
}

type locksmithSignDSSERequest struct {
	Version   string `json:"version"`
	Action    string `json:"action"`
	SessionID string `json:"session_id"`
	PAEB64    string `json:"pae_b64"`
}

type locksmithSignDSSEResponse struct {
	KeyID     string `json:"keyid"`
	KeyIDAlt  string `json:"key_id"`
	Sig       string `json:"sig"`
	SigB64    string `json:"sig_b64"`
	Signature string `json:"signature"`
	Error     string `json:"error,omitempty"`
}

func signDSSEViaLocksmith(ctx context.Context, sockPath, sessionID string, pae []byte) (string, string, error) {
	dialer := &net.Dialer{Timeout: 500 * time.Millisecond}
	conn, err := dialer.DialContext(ctx, "unix", sockPath)
	if err != nil {
		return "", "", err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	req := locksmithSignDSSERequest{
		Version:   "1.0",
		Action:    "sign_dsse",
		SessionID: sessionID,
		PAEB64:    base64.StdEncoding.EncodeToString(pae),
	}
	if err := json.NewEncoder(conn).Encode(&req); err != nil {
		return "", "", err
	}

	var resp locksmithSignDSSEResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return "", "", err
	}
	if resp.Error != "" {
		return "", "", errors.New(resp.Error)
	}

	keyID := resp.KeyID
	if keyID == "" {
		keyID = resp.KeyIDAlt
	}
	sig := resp.Sig
	if sig == "" {
		sig = resp.SigB64
	}
	if sig == "" {
		sig = resp.Signature
	}
	if sig == "" {
		return "", "", errors.New("locksmith returned empty DSSE signature")
	}
	return keyID, sig, nil
}

// validateReceiptDir strictly rejects symlinks on FABRIAL_RECEIPT_DIR and its immediate parent
// (plus every component beneath FABRIAL_WORKTREE_ROOT when set), verifies directory ownership,
// and ensures the directory exists with mode 0700.
func validateReceiptDir(rawDir string) (string, error) {
	if strings.Contains(rawDir, "\x00") {
		return "", fmt.Errorf("%w: NUL byte in FABRIAL_RECEIPT_DIR", ErrReceiptPolicyDeny)
	}
	cleanDir := filepath.Clean(rawDir)
	if cleanDir == "" || cleanDir == "." || cleanDir == string(filepath.Separator) {
		return "", fmt.Errorf("%w: invalid FABRIAL_RECEIPT_DIR", ErrReceiptPolicyDeny)
	}

	// Check the target itself and its immediate parent for symlinks before creating anything.
	if err := rejectIfSymlink(cleanDir); err != nil {
		return "", err
	}
	parent := filepath.Dir(cleanDir)
	if parent != cleanDir {
		if err := rejectIfSymlink(parent); err != nil {
			return "", err
		}
	}

	// If FABRIAL_WORKTREE_ROOT is set, walk every component from worktreeRoot down to cleanDir.
	if wtRoot := strings.TrimSpace(os.Getenv("FABRIAL_WORKTREE_ROOT")); wtRoot != "" {
		cleanWT := filepath.Clean(wtRoot)
		rel, err := filepath.Rel(cleanWT, cleanDir)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			cur := cleanWT
			for _, seg := range strings.Split(rel, string(filepath.Separator)) {
				if seg == "" || seg == "." {
					continue
				}
				cur = filepath.Join(cur, seg)
				if err := rejectIfSymlink(cur); err != nil {
					return "", err
				}
			}
		}
	}

	// Inspect target via Lstat; create with 0700 if absent.
	fi, err := os.Lstat(cleanDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if mkErr := os.MkdirAll(cleanDir, 0o700); mkErr != nil {
				return "", fmt.Errorf("create receipt directory: %w", mkErr)
			}
			fi, err = os.Lstat(cleanDir)
			if err != nil {
				return "", fmt.Errorf("lstat created receipt directory: %w", err)
			}
		} else {
			return "", fmt.Errorf("lstat receipt directory: %w", err)
		}
	}

	if fi.Mode()&os.ModeSymlink != 0 {
		return "", ErrReceiptDirSymlink
	}
	if !fi.IsDir() {
		return "", fmt.Errorf("%w: FABRIAL_RECEIPT_DIR is not a directory", ErrReceiptPolicyDeny)
	}
	if statT, ok := fi.Sys().(*syscall.Stat_t); ok {
		if int(statT.Uid) != os.Geteuid() {
			return "", fmt.Errorf("%w: FABRIAL_RECEIPT_DIR owner UID mismatch", ErrReceiptPolicyDeny)
		}
	}

	return cleanDir, nil
}

func rejectIfSymlink(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("lstat %s: %w", path, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return ErrReceiptDirSymlink
	}
	return nil
}

// writeAtomicReceipt opens cleanDir with os.OpenRoot, writes to a unique O_CREAT|O_EXCL|O_NOFOLLOW
// 0600 temp file, fsyncs, closes, and atomically renames into finalName inside the root.
func writeAtomicReceipt(cleanDir, finalName string, data []byte) error {
	root, err := os.OpenRoot(cleanDir)
	if err != nil {
		return fmt.Errorf("%w: open root receipt directory: %v", ErrReceiptPolicyDeny, err)
	}
	defer root.Close()

	// Double-check the opened directory itself was not swapped to a symlink.
	if fi, err := os.Lstat(cleanDir); err != nil || fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return ErrReceiptDirSymlink
	}

	tmpName := fmt.Sprintf(".tmp-%s", generatePrefixedID(""))
	f, err := root.OpenFile(tmpName, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("create temp receipt file: %w", err)
	}

	cleanupTmp := true
	defer func() {
		if cleanupTmp {
			_ = root.Remove(tmpName)
		}
	}()

	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return fmt.Errorf("chmod temp receipt file: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("write receipt payload: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("fsync receipt file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close receipt file: %w", err)
	}

	if err := root.Rename(tmpName, finalName); err != nil {
		return fmt.Errorf("atomic rename receipt file: %w", err)
	}
	cleanupTmp = false
	return nil
}

func resolveWorktreeHeadSHA() string {
	dir := strings.TrimSpace(os.Getenv("FABRIAL_WORKTREE_ROOT"))
	if ctx := gitscope.Detect(dir); ctx.IsGit {
		sha := strings.ToLower(strings.TrimSpace(ctx.Commit))
		if blprHeadSHARe.MatchString(sha) {
			return sha
		}
	}
	return "0000000"
}

func normalizeSessionID(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	if blprSessionRe.MatchString(trimmed) {
		return trimmed
	}
	trimmed = strings.TrimPrefix(trimmed, "sess_")
	var b strings.Builder
	for _, r := range trimmed {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return ""
	}
	return "sess_" + b.String()
}

func normalizeReceiptID(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	if ubReceiptRe.MatchString(trimmed) {
		return trimmed
	}
	trimmed = strings.TrimPrefix(trimmed, "rcpt_")
	var b strings.Builder
	for _, r := range trimmed {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return ""
	}
	return "rcpt_" + b.String()
}

func generatePrefixedID(prefix string) string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return prefix + hex.EncodeToString(b[:])
}
