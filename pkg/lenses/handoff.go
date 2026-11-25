package lenses

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/scope"
	"github.com/bonjoski/coppermind/pkg/security"
)

const (
	// DefaultEvalTokenTTL is the lifetime of a single-use host-evaluated lens token.
	DefaultEvalTokenTTL = 15 * time.Minute

	// HostEvalSubmitTool is the canonical MCP tool that accepts host-evaluated lens findings.
	HostEvalSubmitTool = "coppermind_lens_submit"

	// TierDerivedObservation is the authority tier ceiling for host-evaluated derived observations.
	TierDerivedObservation = "TIER_3_DERIVED"

	// SkipReasonPrefilterNoSinks indicates the zero-cost pre-filter gate bypassed the candidate.
	SkipReasonPrefilterNoSinks = "prefilter_no_sinks"

	// SkipReasonDerivedCandidate indicates the candidate is already a derived observation (anti-recursion).
	SkipReasonDerivedCandidate = "derived_candidate"

	// HostFindingsOutputSchema documents the strict JSON schema expected by coppermind_lens_submit.
	HostFindingsOutputSchema = `{"findings":[{"severity":"info|low|medium|high|critical","category":"differential_auth|unintended_side_effect|sink_injection|boundary_leak|layer_inversion|circular_dependency|adr_violation|hygiene|synthesis|exploit|counterargument","entry_point":"string","sibling_inconsistency":"string","summary":"string","evidence":"string","poc":"executable reproduction command or payload"}]}`

	evalTokenVersion = "cmlens1"
	evalReplayShards = 16
)

var (
	// ErrEvalTokenInvalid indicates a malformed, untrusted, or signature-mismatched eval_token.
	ErrEvalTokenInvalid = errors.New("eval_token invalid or forged")
	// ErrEvalTokenExpired indicates an eval_token has passed its expiration timestamp.
	ErrEvalTokenExpired = errors.New("eval_token expired")
	// ErrEvalTokenReplayed indicates an eval_token was already redeemed.
	ErrEvalTokenReplayed = errors.New("eval_token already redeemed (replay rejected)")
	// ErrEvalTokenSessionMismatch indicates the submit session_id does not match the bound token session.
	ErrEvalTokenSessionMismatch = errors.New("eval_token session_id mismatch")
	// ErrInvalidFindingsJSON indicates the host model returned malformed or non-JSON findings.
	ErrInvalidFindingsJSON = errors.New("invalid findings JSON")
	// ErrUnknownLens indicates the requested lens is not configured.
	ErrUnknownLens = errors.New("unknown lens")

	rePrivateKeyBlock = regexp.MustCompile(`-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED|ED25519) )?PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END (?:(?:RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED|ED25519) )?PRIVATE KEY(?: BLOCK)?-----`)
	rePrivateKeyLine  = regexp.MustCompile(`(?m)^.*-----BEGIN .*PRIVATE KEY.*$`)
)

// EvalTokenClaims cryptographically binds a host-evaluated lens prompt to its exact
// candidate artifact and lens config, preventing cross-lens or forged submission injection.
type EvalTokenClaims struct {
	TokenID      string    `json:"tid"`
	Project      string    `json:"proj"`
	SessionID    string    `json:"sess"`
	LensName     string    `json:"lens"`
	TargetID     string    `json:"target_id,omitempty"`
	TargetSHA256 string    `json:"target_sha256"`
	IssuedAt     time.Time `json:"iat"`
	ExpiresAt    time.Time `json:"exp"`
}

// PreparedLensBundle is returned by coppermind_lens_prepare for zero-API-key evaluation
// by the user's already-authenticated IDE model (Claude, Cursor, Gemini, Codex).
type PreparedLensBundle struct {
	Skipped      bool      `json:"skipped"`
	SkipReason   string    `json:"skip_reason,omitempty"`
	EvalToken    string    `json:"eval_token,omitempty"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
	LensName     string    `json:"lens"`
	SystemPrompt string    `json:"system_prompt,omitempty"`
	UserPrompt   string    `json:"user_prompt,omitempty"`
	OutputSchema string    `json:"output_schema,omitempty"`
	SubmitTool   string    `json:"submit_tool,omitempty"`
}

// HostEvalSubmissionResult summarizes deterministic PoC-gate & quarantine outcomes.
type HostEvalSubmissionResult struct {
	LensName          string              `json:"lens"`
	AcceptedCount     int                 `json:"accepted_count"`
	DemotedNoPoCCount int                 `json:"demoted_no_poc_count"`
	DeduplicatedCount int                 `json:"deduplicated_count"`
	Observations      []*brain.MemoryNode `json:"observations,omitempty"`
	ReceiptID         string              `json:"receipt_id,omitempty"`
}

// HostEvaluator prepares fenced bundles and validates/ingests host-evaluated JSON findings.
type HostEvaluator interface {
	Prepare(ctx context.Context, lens *LensConfig, candidate *brain.MemoryNode, force bool) (*PreparedLensBundle, error)
	Submit(ctx context.Context, evalToken string, rawFindings string, sessionID string) (*HostEvalSubmissionResult, error)
}

// ParseAndSanitizeHostFindings parses raw host-evaluated JSON findings by reusing
// Coppermind's canonical parseAndSanitizeResponse and EnforcePoCGate pipelines.
func ParseAndSanitizeHostFindings(lensName string, rawContent string) (*ModelResponse, error) {
	if strings.TrimSpace(rawContent) == "" || extractJSON(rawContent) == "" {
		return nil, fmt.Errorf("%w: expected JSON object {\"findings\": [...]}", ErrInvalidFindingsJSON)
	}

	modelResp, err := parseAndSanitizeResponse(rawContent)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidFindingsJSON, err)
	}

	enforceAll := strings.EqualFold(strings.TrimSpace(lensName), "security-architect")
	for i := range modelResp.Findings {
		f := &modelResp.Findings[i]

		// Defense-in-depth secret quarantine on remaining auxiliary fields.
		if f.EntryPoint != "" {
			if secRes, sErr := security.SanitizeMemory(f.EntryPoint); sErr != nil {
				f.EntryPoint = "[REDACTED_PRIVATE_KEY]"
			} else {
				f.EntryPoint = secRes.SanitizedText
			}
		}
		if f.SiblingInconsistency != "" {
			if secRes, sErr := security.SanitizeMemory(f.SiblingInconsistency); sErr != nil {
				f.SiblingInconsistency = "[REDACTED_PRIVATE_KEY]"
			} else {
				f.SiblingInconsistency = secRes.SanitizedText
			}
		}

		if enforceAll {
			EnforcePoCGate(f)
		}
	}

	return modelResp, nil
}

type evalReplayShard struct {
	mu   sync.Mutex
	used map[string]time.Time
}

// DefaultHostEvaluator implements HostEvaluator with an ephemeral per-process 256-bit CSPRNG
// HMAC-SHA256 signing key and a 16-shard lock-striped single-use replay cache.
type DefaultHostEvaluator struct {
	manager      *brain.Manager
	project      string
	config       *LensesConfig
	signingKey   []byte
	ttl          time.Duration
	nowFn        func() time.Time
	replayShards [evalReplayShards]evalReplayShard
}

var _ HostEvaluator = (*DefaultHostEvaluator)(nil)

// NewDefaultHostEvaluator constructs a DefaultHostEvaluator backed by a fresh 256-bit CSPRNG HMAC key.
func NewDefaultHostEvaluator(mgr *brain.Manager, projectName string, cfg *LensesConfig) (*DefaultHostEvaluator, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if strings.TrimSpace(projectName) == "" {
		projectName = "default"
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed generating ephemeral host-eval HMAC key: %w", err)
	}

	ev := &DefaultHostEvaluator{
		manager:    mgr,
		project:    projectName,
		config:     cfg,
		signingKey: key,
		ttl:        DefaultEvalTokenTTL,
		nowFn:      time.Now,
	}
	for i := range ev.replayShards {
		ev.replayShards[i].used = make(map[string]time.Time)
	}
	return ev, nil
}

// SetTTL overrides the eval_token TTL (primarily for testing).
func (e *DefaultHostEvaluator) SetTTL(d time.Duration) {
	if d > 0 {
		e.ttl = d
	}
}

// SetNowFunc overrides the clock source (primarily for deterministic expiry testing).
func (e *DefaultHostEvaluator) SetNowFunc(fn func() time.Time) {
	if fn != nil {
		e.nowFn = fn
	}
}

func (e *DefaultHostEvaluator) now() time.Time {
	if e.nowFn != nil {
		return e.nowFn().UTC()
	}
	return time.Now().UTC()
}

// Prepare executes the zero-cost pre-filter, redacts candidate secrets, retrieves sibling endpoints
// and recalled context, builds an XML-fenced prompt, and mints a signed single-use eval_token.
func (e *DefaultHostEvaluator) Prepare(ctx context.Context, lens *LensConfig, candidate *brain.MemoryNode, force bool) (*PreparedLensBundle, error) {
	return e.PrepareWithManager(ctx, e.manager, e.project, lens, candidate, force)
}

// PrepareWithManager prepares a lens bundle against an explicit brain manager and project vault name.
func (e *DefaultHostEvaluator) PrepareWithManager(ctx context.Context, mgr *brain.Manager, projectName string, lens *LensConfig, candidate *brain.MemoryNode, force bool) (*PreparedLensBundle, error) {
	if lens == nil {
		return nil, fmt.Errorf("%w: nil lens config", ErrUnknownLens)
	}
	if candidate == nil {
		return nil, fmt.Errorf("candidate artifact is required")
	}
	if lens.PrefilterRegex != "" && lens.compiledRegex == nil {
		if err := lens.Compile(); err != nil {
			return nil, err
		}
	}
	if strings.TrimSpace(projectName) == "" {
		projectName = e.project
	}
	if strings.TrimSpace(projectName) == "" {
		projectName = "default"
	}

	// Anti-recursion invariant: never evaluate derived records.
	if candidate.Derived {
		return &PreparedLensBundle{
			Skipped:    true,
			SkipReason: SkipReasonDerivedCandidate,
			LensName:   lens.Name,
		}, nil
	}

	// 1. Zero-cost Pre-Filter Gate.
	if !force && !lens.MatchesPrefilter(candidate.Content) {
		return &PreparedLensBundle{
			Skipped:    true,
			SkipReason: SkipReasonPrefilterNoSinks,
			LensName:   lens.Name,
		}, nil
	}

	// 2. Redact candidate secrets before handing content to host AI.
	sanitizedContent := redactCandidateSecrets(candidate.Content)
	sanitizedCandidate := cloneMemoryNodeWithContent(candidate, sanitizedContent)

	// 3. Recall relevant project/radar context and sibling endpoints.
	var contextMemories []*brain.MemoryNode
	var siblings []*brain.MemoryNode
	if mgr != nil {
		contextMemories = recallContextForLens(ctx, mgr, lens, sanitizedCandidate)
		siblings = recallSiblingsForCandidate(ctx, mgr, sanitizedCandidate)
	}

	// 4. Build strict OWASP LLM01 XML-fenced prompts.
	sysPrompt, userPrompt := BuildEvaluationPromptWithSiblings(lens, sanitizedCandidate, contextMemories, siblings)

	// 5. Compute SHA-256 digest of candidate content and mint signed eval_token.
	digest := sha256.Sum256([]byte(sanitizedCandidate.Content))
	targetSHA := hex.EncodeToString(digest[:])

	now := e.now()
	expiresAt := now.Add(e.ttl)
	tokenID, err := generateEvalTokenID()
	if err != nil {
		return nil, err
	}

	claims := EvalTokenClaims{
		TokenID:      tokenID,
		Project:      projectName,
		SessionID:    strings.TrimSpace(candidate.SessionID),
		LensName:     lens.Name,
		TargetID:     strings.TrimSpace(candidate.ID),
		TargetSHA256: targetSHA,
		IssuedAt:     now,
		ExpiresAt:    expiresAt,
	}
	token, err := e.signToken(claims)
	if err != nil {
		return nil, err
	}

	return &PreparedLensBundle{
		Skipped:      false,
		EvalToken:    token,
		ExpiresAt:    expiresAt,
		LensName:     lens.Name,
		SystemPrompt: sysPrompt,
		UserPrompt:   userPrompt,
		OutputSchema: HostFindingsOutputSchema,
		SubmitTool:   HostEvalSubmitTool,
	}, nil
}

// VerifyTokenClaims validates HMAC signature, token structure, and expiration without consuming
// the single-use replay cache. Used by callers needing to inspect bound project metadata first.
func (e *DefaultHostEvaluator) VerifyTokenClaims(evalToken string) (*EvalTokenClaims, error) {
	claims, err := e.verifySignatureAndDecode(evalToken)
	if err != nil {
		return nil, err
	}
	if !e.now().Before(claims.ExpiresAt) {
		return nil, ErrEvalTokenExpired
	}
	return claims, nil
}

// Submit validates the eval_token (HMAC, expiry, session binding, single-use replay), runs
// ParseAndSanitizeHostFindings, deduplicates via ComputeDedupHash, and persists derived observations.
func (e *DefaultHostEvaluator) Submit(ctx context.Context, evalToken string, rawFindings string, sessionID string) (*HostEvalSubmissionResult, error) {
	return e.SubmitWithManager(ctx, e.manager, evalToken, rawFindings, sessionID)
}

// SubmitWithManager validates and persists host-evaluated findings into the specified brain manager.
func (e *DefaultHostEvaluator) SubmitWithManager(ctx context.Context, mgr *brain.Manager, evalToken string, rawFindings string, sessionID string) (*HostEvalSubmissionResult, error) {
	// 1. Verify HMAC signature and decode claims (constant-time).
	claims, err := e.verifySignatureAndDecode(evalToken)
	if err != nil {
		return nil, err
	}

	// 2. Enforce token TTL expiry.
	now := e.now()
	if !now.Before(claims.ExpiresAt) {
		return nil, ErrEvalTokenExpired
	}

	// 3. Enforce session binding when the token is bound to a non-empty session.
	cleanSession := strings.TrimSpace(sessionID)
	if claims.SessionID != "" && cleanSession != claims.SessionID {
		return nil, fmt.Errorf("%w: token bound to session %q", ErrEvalTokenSessionMismatch, claims.SessionID)
	}

	// 4. Enforce single-use replay protection via 16-shard lock-striped cache.
	if err := e.consumeTokenReplay(claims.TokenID, claims.ExpiresAt, now); err != nil {
		return nil, err
	}

	// 5. Parse, sanitize, quarantine secrets, and enforce PoC gate via shared pipeline.
	modelResp, err := ParseAndSanitizeHostFindings(claims.LensName, rawFindings)
	if err != nil {
		return nil, err
	}

	result := &HostEvalSubmissionResult{
		LensName: claims.LensName,
	}

	if len(modelResp.Findings) == 0 {
		return result, nil
	}

	obsSessionID := claims.SessionID
	if obsSessionID == "" {
		obsSessionID = cleanSession
	}
	if obsSessionID == "" {
		obsSessionID = "default"
	}

	var parentIDs []string
	if claims.TargetID != "" {
		parentIDs = []string{claims.TargetID}
	}

	// 6. Persist verified derived observations with ComputeDedupHash idempotency.
	for _, finding := range modelResp.Findings {
		if finding.UnverifiedPoC {
			result.DemotedNoPoCCount++
		}

		dedupHash := ComputeDedupHash(claims.Project, claims.LensName, claims.TargetSHA256, finding.Summary)

		if mgr != nil {
			if existing, err := mgr.GetByDedupHash(ctx, dedupHash); err == nil && existing != nil {
				result.DeduplicatedCount++
				continue
			}
		}

		obsContent := formatObservationContent(claims.LensName, finding)
		meta := buildObservationMetadata(claims, finding)

		if mgr != nil {
			obsNode, err := mgr.Remember(ctx, brain.RememberRequest{
				SessionID:     obsSessionID,
				Category:      "observation",
				Content:       obsContent,
				Provenance:    brain.ProvenanceLocalWorkspace,
				Metadata:      meta,
				Derived:       true,
				SourceLens:    claims.LensName,
				ParentIDs:     parentIDs,
				Severity:      finding.Severity,
				Status:        "open",
				DedupHash:     dedupHash,
				Deduplicate:   false,
				AuthorityTier: TierDerivedObservation,
			})
			if err != nil {
				return result, fmt.Errorf("failed to persist host-evaluated observation: %w", err)
			}
			result.Observations = append(result.Observations, obsNode)
		}
		result.AcceptedCount++
	}

	return result, nil
}

func (e *DefaultHostEvaluator) signToken(claims EvalTokenClaims) (string, error) {
	rawClaims, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal eval_token claims: %w", err)
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(rawClaims)
	signingInput := evalTokenVersion + "." + payloadB64

	mac := hmac.New(sha256.New, e.signingKey)
	_, _ = mac.Write([]byte(signingInput))
	sigB64 := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return signingInput + "." + sigB64, nil
}

func (e *DefaultHostEvaluator) verifySignatureAndDecode(evalToken string) (*EvalTokenClaims, error) {
	trimmed := strings.TrimSpace(evalToken)
	parts := strings.Split(trimmed, ".")
	if len(parts) != 3 || parts[0] != evalTokenVersion || parts[1] == "" || parts[2] == "" {
		return nil, ErrEvalTokenInvalid
	}

	gotMAC, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(gotMAC) != sha256.Size {
		return nil, ErrEvalTokenInvalid
	}

	signingInput := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, e.signingKey)
	_, _ = mac.Write([]byte(signingInput))
	expectedMAC := mac.Sum(nil)

	if !hmac.Equal(expectedMAC, gotMAC) {
		return nil, ErrEvalTokenInvalid
	}

	rawClaims, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrEvalTokenInvalid
	}

	var claims EvalTokenClaims
	if err := json.Unmarshal(rawClaims, &claims); err != nil {
		return nil, ErrEvalTokenInvalid
	}

	if claims.TokenID == "" || claims.LensName == "" || claims.TargetSHA256 == "" || claims.ExpiresAt.IsZero() {
		return nil, ErrEvalTokenInvalid
	}
	return &claims, nil
}

func (e *DefaultHostEvaluator) consumeTokenReplay(tokenID string, expiresAt, now time.Time) error {
	shardIdx := fnv1aShardIndex(tokenID)
	shard := &e.replayShards[shardIdx]

	shard.mu.Lock()
	defer shard.mu.Unlock()

	if exp, exists := shard.used[tokenID]; exists {
		if now.Before(exp) {
			return ErrEvalTokenReplayed
		}
		delete(shard.used, tokenID)
	}

	// Opportunistically prune expired entries to keep memory strictly bounded.
	if len(shard.used) >= 64 {
		for id, exp := range shard.used {
			if !now.Before(exp) {
				delete(shard.used, id)
			}
		}
	}

	shard.used[tokenID] = expiresAt
	return nil
}

func fnv1aShardIndex(s string) int {
	var h uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return int(h & (evalReplayShards - 1))
}

func generateEvalTokenID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("failed generating eval_token ID: %w", err)
	}
	return "etok_" + hex.EncodeToString(b[:]), nil
}

// redactCandidateSecrets redacts private keys and embedded credentials from candidate artifacts
// before handing them to the host AI model so raw secrets never leave Coppermind.
func redactCandidateSecrets(content string) string {
	// First scrub any private key blocks so security.SanitizeMemory can still redact
	// remaining inline tokens without aborting the entire artifact.
	cleaned := rePrivateKeyBlock.ReplaceAllString(content, "[REDACTED_PRIVATE_KEY]")
	cleaned = rePrivateKeyLine.ReplaceAllString(cleaned, "[REDACTED_PRIVATE_KEY]")

	secRes, err := security.SanitizeMemory(cleaned)
	if err != nil {
		return "[REDACTED_SECRET_ARTIFACT]"
	}
	return secRes.SanitizedText
}

func cloneMemoryNodeWithContent(src *brain.MemoryNode, content string) *brain.MemoryNode {
	cp := *src
	cp.Content = content
	if src.Metadata != nil {
		cp.Metadata = make(map[string]string, len(src.Metadata))
		for k, v := range src.Metadata {
			cp.Metadata[k] = v
		}
	}
	if cp.CreatedAt.IsZero() {
		cp.CreatedAt = time.Now().UTC()
	}
	return &cp
}

func recallContextForLens(ctx context.Context, mgr *brain.Manager, lens *LensConfig, candidate *brain.MemoryNode) []*brain.MemoryNode {
	if mgr == nil || len(lens.RecallCategories) == 0 || strings.TrimSpace(candidate.Content) == "" {
		return nil
	}

	var out []*brain.MemoryNode
	seen := make(map[string]bool)
	if candidate.ID != "" {
		seen[candidate.ID] = true
	}

	falseDerived := false
	var scMode scope.Mode
	if candidate.Scope != "" {
		scMode = scope.ModeAncestors
	}
	for _, cat := range lens.RecallCategories {
		recalled, err := mgr.Recall(ctx, brain.RecallRequest{
			SessionID:   candidate.SessionID,
			Category:    cat,
			Scope:       candidate.Scope,
			ScopeMode:   scMode,
			ActiveScope: candidate.Scope,
			Query:       candidate.Content,
			Limit:       3,
			MinScore:    0.0,
			Hybrid:      true,
			Derived:     &falseDerived,
		})
		if (err != nil || len(recalled) == 0) && candidate.SessionID != "" {
			// Fallback to project-wide recall (preserving scope ancestor inheritance) so shared ADRs and industry_radar baselines are included.
			recalled, err = mgr.Recall(ctx, brain.RecallRequest{
				Category:    cat,
				Scope:       candidate.Scope,
				ScopeMode:   scMode,
				ActiveScope: candidate.Scope,
				Query:       candidate.Content,
				Limit:       3,
				MinScore:    0.0,
				Hybrid:      true,
				Derived:     &falseDerived,
			})
		}
		if err != nil {
			continue
		}
		for _, r := range recalled {
			if r != nil && r.Node != nil && !r.Node.Derived && !seen[r.Node.ID] {
				seen[r.Node.ID] = true
				out = append(out, r.Node)
			}
		}
	}
	return out
}

func recallSiblingsForCandidate(ctx context.Context, mgr *brain.Manager, candidate *brain.MemoryNode) []*brain.MemoryNode {
	if mgr == nil || candidate == nil {
		return nil
	}
	siblings := RetrieveSiblingEndpoints(ctx, mgr, candidate)
	if len(siblings) == 0 && candidate.SessionID != "" {
		globalCand := cloneMemoryNodeWithContent(candidate, candidate.Content)
		globalCand.SessionID = ""
		siblings = RetrieveSiblingEndpoints(ctx, mgr, globalCand)
	}
	return siblings
}

func formatObservationContent(lensName string, finding Finding) string {
	obsContent := fmt.Sprintf("[%s] %s: %s", strings.ToUpper(finding.Severity), lensName, finding.Summary)
	if finding.Evidence != "" {
		obsContent += fmt.Sprintf("\nEvidence: %s", finding.Evidence)
	}
	if finding.EntryPoint != "" {
		obsContent += fmt.Sprintf("\nEntry Point: %s", finding.EntryPoint)
	}
	if finding.SiblingInconsistency != "" {
		obsContent += fmt.Sprintf("\nSibling Inconsistency: %s", finding.SiblingInconsistency)
	}
	if finding.PoC != "" {
		obsContent += fmt.Sprintf("\nPoC: %s", finding.PoC)
	}
	return obsContent
}

func buildObservationMetadata(claims *EvalTokenClaims, finding Finding) map[string]string {
	meta := map[string]string{
		"lens":             claims.LensName,
		"severity":         finding.Severity,
		"finding_category": finding.Category,
		"project":          claims.Project,
		"eval_mode":        "host_evaluated",
		"target_sha256":    claims.TargetSHA256,
	}
	if finding.EntryPoint != "" {
		meta["entry_point"] = finding.EntryPoint
	}
	if finding.SiblingInconsistency != "" {
		meta["sibling_inconsistency"] = finding.SiblingInconsistency
	}
	if finding.PoC != "" {
		meta["poc"] = finding.PoC
	}
	if finding.UnverifiedPoC {
		meta["unverified_poc"] = "true"
	}
	return meta
}
