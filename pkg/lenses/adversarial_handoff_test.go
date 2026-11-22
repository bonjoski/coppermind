package lenses

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/embedding"
	"github.com/bonjoski/coppermind/pkg/scratchpad"
	"github.com/bonjoski/coppermind/pkg/storage/sqlite"
)

func newTestHostEvalBrain(t *testing.T) *brain.Manager {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "host_eval_test.db")
	store, err := sqlite.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed creating sqlite store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	embedder := embedding.NewLocalHashEmbedder(128)
	sp := scratchpad.NewMemoryScratchpad()
	return brain.NewManager(store, embedder, sp)
}

func TestHostEval_RejectsForgedExpiredAndReplayedEvalTokens(t *testing.T) {
	ctx := context.Background()
	mgr := newTestHostEvalBrain(t)
	cfg := DefaultConfig()
	secLens, ok := cfg.GetLens("security-architect")
	if !ok {
		t.Fatal("security-architect lens missing from default config")
	}

	ev, err := NewDefaultHostEvaluator(mgr, "testproj", cfg)
	if err != nil {
		t.Fatalf("NewDefaultHostEvaluator failed: %v", err)
	}

	baseNow := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	var currentNow time.Time = baseNow
	ev.SetNowFunc(func() time.Time { return currentNow })

	cand := &brain.MemoryNode{
		ID:        "mem_cand_1",
		SessionID: "sess_alpha",
		Category:  "code",
		Content:   `func (h *Handler) DeleteItemHandler(w http.ResponseWriter, r *http.Request) { exec.Command("rm", r.URL.Query().Get("id")) }`,
		CreatedAt: baseNow,
	}

	bundle, err := ev.Prepare(ctx, secLens, cand, false)
	if err != nil {
		t.Fatalf("Prepare failed: %v", err)
	}
	if bundle.Skipped || bundle.EvalToken == "" {
		t.Fatalf("expected non-skipped bundle with eval_token, got: %+v", bundle)
	}

	validFindings := `{"findings":[{"severity":"high","category":"sink_injection","entry_point":"DeleteItemHandler","summary":"Command injection via query param","poc":"curl 'http://localhost:8080/delete?id=;id'"}]}`

	// 1. Forged signature (tampered HMAC byte)
	parts := strings.Split(bundle.EvalToken, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3-part eval_token, got %d parts", len(parts))
	}
	tamperedSig := parts[2]
	if tamperedSig[0] == 'A' {
		tamperedSig = "B" + tamperedSig[1:]
	} else {
		tamperedSig = "A" + tamperedSig[1:]
	}
	forgedSigToken := parts[0] + "." + parts[1] + "." + tamperedSig
	if _, err := ev.Submit(ctx, forgedSigToken, validFindings, "sess_alpha"); !errors.Is(err, ErrEvalTokenInvalid) {
		t.Fatalf("expected ErrEvalTokenInvalid for tampered signature, got: %v", err)
	}

	// 2. Forged claims with attacker-controlled payload
	fakeClaims, _ := json.Marshal(EvalTokenClaims{
		TokenID:      "etok_forged",
		Project:      "otherproj",
		SessionID:    "sess_alpha",
		LensName:     "security-architect",
		TargetSHA256: strings.Repeat("a", 64),
		IssuedAt:     baseNow,
		ExpiresAt:    baseNow.Add(15 * time.Minute),
	})
	forgedClaimsToken := evalTokenVersion + "." + base64.RawURLEncoding.EncodeToString(fakeClaims) + "." + parts[2]
	if _, err := ev.Submit(ctx, forgedClaimsToken, validFindings, "sess_alpha"); !errors.Is(err, ErrEvalTokenInvalid) {
		t.Fatalf("expected ErrEvalTokenInvalid for forged claims, got: %v", err)
	}

	// 3. Token signed by a completely separate evaluator instance (different CSPRNG key)
	otherEv, err := NewDefaultHostEvaluator(mgr, "testproj", cfg)
	if err != nil {
		t.Fatalf("other NewDefaultHostEvaluator failed: %v", err)
	}
	otherEv.SetNowFunc(func() time.Time { return currentNow })
	otherBundle, err := otherEv.Prepare(ctx, secLens, cand, false)
	if err != nil {
		t.Fatalf("other Prepare failed: %v", err)
	}
	if _, err := ev.Submit(ctx, otherBundle.EvalToken, validFindings, "sess_alpha"); !errors.Is(err, ErrEvalTokenInvalid) {
		t.Fatalf("expected ErrEvalTokenInvalid for cross-instance key token, got: %v", err)
	}

	// 4. Malformed / empty tokens
	for _, bad := range []string{"", "not-a-token", "cmlens1.onlytwo", "wrongver.abc.def"} {
		if _, err := ev.Submit(ctx, bad, validFindings, "sess_alpha"); !errors.Is(err, ErrEvalTokenInvalid) {
			t.Fatalf("expected ErrEvalTokenInvalid for %q, got: %v", bad, err)
		}
	}

	// 5. Session mismatch when token is bound to sess_alpha
	if _, err := ev.Submit(ctx, bundle.EvalToken, validFindings, "sess_beta"); !errors.Is(err, ErrEvalTokenSessionMismatch) {
		t.Fatalf("expected ErrEvalTokenSessionMismatch for wrong session, got: %v", err)
	}
	if _, err := ev.Submit(ctx, bundle.EvalToken, validFindings, ""); !errors.Is(err, ErrEvalTokenSessionMismatch) {
		t.Fatalf("expected ErrEvalTokenSessionMismatch for empty session on bound token, got: %v", err)
	}

	// 6. Expired token (advance clock beyond 15-minute TTL)
	expiredBundle, err := ev.Prepare(ctx, secLens, cand, false)
	if err != nil {
		t.Fatalf("Prepare expiredBundle failed: %v", err)
	}
	currentNow = baseNow.Add(DefaultEvalTokenTTL + time.Second)
	if _, err := ev.Submit(ctx, expiredBundle.EvalToken, validFindings, "sess_alpha"); !errors.Is(err, ErrEvalTokenExpired) {
		t.Fatalf("expected ErrEvalTokenExpired after TTL, got: %v", err)
	}

	// Reset clock within TTL and redeem original bundle once -> must succeed
	currentNow = baseNow.Add(2 * time.Minute)
	subRes, err := ev.Submit(ctx, bundle.EvalToken, validFindings, "sess_alpha")
	if err != nil {
		t.Fatalf("valid Submit failed: %v", err)
	}
	if subRes.AcceptedCount != 1 || subRes.DemotedNoPoCCount != 0 {
		t.Fatalf("unexpected valid submission result: %+v", subRes)
	}

	// 7. Replayed token -> must fail closed with ErrEvalTokenReplayed
	if _, err := ev.Submit(ctx, bundle.EvalToken, validFindings, "sess_alpha"); !errors.Is(err, ErrEvalTokenReplayed) {
		t.Fatalf("expected ErrEvalTokenReplayed on second redemption, got: %v", err)
	}

	// 8. Invalid JSON findings payload -> must fail closed with ErrInvalidFindingsJSON
	badJSONBundle, err := ev.Prepare(ctx, secLens, cand, false)
	if err != nil {
		t.Fatalf("Prepare badJSONBundle failed: %v", err)
	}
	if _, err := ev.Submit(ctx, badJSONBundle.EvalToken, "This is plain prose with no JSON", "sess_alpha"); !errors.Is(err, ErrInvalidFindingsJSON) {
		t.Fatalf("expected ErrInvalidFindingsJSON for prose payload, got: %v", err)
	}
}

func TestHostEval_SanitizesPrivateKeysAndDemotesMissingPoC(t *testing.T) {
	ctx := context.Background()
	mgr := newTestHostEvalBrain(t)
	cfg := DefaultConfig()
	secLens, _ := cfg.GetLens("security-architect")

	ev, err := NewDefaultHostEvaluator(mgr, "secvault", cfg)
	if err != nil {
		t.Fatalf("NewDefaultHostEvaluator failed: %v", err)
	}

	// Candidate embeds both a raw RSA private key and an AWS access key; Prepare must redact before prompting host AI.
	rawAWSKey := "AKIAIOSFODNN7EXAMPLE"
	rawPrivKey := "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0fakeKeyMaterial1234567890\n-----END RSA PRIVATE KEY-----"
	cand := &brain.MemoryNode{
		ID:        "mem_secret_handler",
		SessionID: "sess_sec",
		Category:  "code",
		Content: fmt.Sprintf(`func (h *Handler) AuthHandler(w http.ResponseWriter, r *http.Request) {
	awsKey := %q
	pem := %q
	_ = awsKey + pem
}`, rawAWSKey, rawPrivKey),
		CreatedAt: time.Now().UTC(),
	}

	bundle, err := ev.Prepare(ctx, secLens, cand, false)
	if err != nil {
		t.Fatalf("Prepare failed: %v", err)
	}
	if bundle.Skipped {
		t.Fatalf("expected AuthHandler candidate not to be skipped")
	}
	if strings.Contains(bundle.UserPrompt, "BEGIN RSA PRIVATE KEY") || strings.Contains(bundle.UserPrompt, "MIIEowIBAAKCAQEA0") {
		t.Fatalf("Prepare leaked raw private key into UserPrompt:\n%s", bundle.UserPrompt)
	}
	if strings.Contains(bundle.UserPrompt, rawAWSKey) {
		t.Fatalf("Prepare leaked raw AWS access key into UserPrompt:\n%s", bundle.UserPrompt)
	}
	if !strings.Contains(bundle.UserPrompt, "[REDACTED_PRIVATE_KEY]") || !strings.Contains(bundle.UserPrompt, "[REDACTED_AWS_KEY]") {
		t.Fatalf("expected redaction markers in UserPrompt:\n%s", bundle.UserPrompt)
	}

	// Host AI submits 3 findings:
	// 1. Valid critical finding with executable curl PoC -> preserved as critical
	// 2. High finding without PoC -> demoted to info (UnverifiedPoC=true)
	// 3. Critical finding embedding a raw OpenSSH private key in PoC & summary -> redacted + demoted
	hostFindings := `{
		"findings": [
			{
				"severity": "critical",
				"category": "differential_auth",
				"entry_point": "AuthHandler",
				"sibling_inconsistency": "Sibling verifies tenant JWT; AuthHandler omits check",
				"summary": "Cross-tenant authorization bypass on AuthHandler",
				"poc": "curl -X POST http://localhost:8080/auth/override -H 'X-Tenant: victim'"
			},
			{
				"severity": "high",
				"category": "differential_auth",
				"entry_point": "AuthHandler",
				"summary": "Unverified speculative auth issue with no PoC",
				"poc": "TODO verify manually later"
			},
			{
				"severity": "critical",
				"category": "sink_injection",
				"entry_point": "AuthHandler",
				"summary": "Leaked key material: -----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU=\n-----END OPENSSH PRIVATE KEY-----",
				"poc": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU=\n-----END OPENSSH PRIVATE KEY-----"
			}
		]
	}`

	res, err := ev.Submit(ctx, bundle.EvalToken, hostFindings, "sess_sec")
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}
	if res.AcceptedCount != 3 {
		t.Fatalf("expected 3 accepted observations, got %d", res.AcceptedCount)
	}
	if res.DemotedNoPoCCount != 2 {
		t.Fatalf("expected 2 demoted findings (missing PoC + redacted private-key PoC), got %d", res.DemotedNoPoCCount)
	}
	if len(res.Observations) != 3 {
		t.Fatalf("expected 3 persisted observation nodes, got %d", len(res.Observations))
	}

	// Verify invariants on every persisted observation
	var foundValidCritical bool
	for _, obs := range res.Observations {
		if !obs.Derived {
			t.Errorf("observation %s must have Derived=true", obs.ID)
		}
		if obs.AuthorityTier != TierDerivedObservation && obs.AuthorityTier != "TIER_4_SCRATCHPAD" {
			t.Errorf("observation %s escalated above %s: got %q", obs.ID, TierDerivedObservation, obs.AuthorityTier)
		}
		if strings.Contains(obs.Content, "BEGIN OPENSSH PRIVATE KEY") || strings.Contains(obs.Content, "b3BlbnNzaC1rZXktdjE") {
			t.Fatalf("raw private key leaked into persisted observation %s: %s", obs.ID, obs.Content)
		}
		if strings.Contains(obs.Content, "Cross-tenant authorization bypass") {
			if obs.Severity != "critical" {
				t.Errorf("valid PoC critical finding should keep severity 'critical', got %q", obs.Severity)
			}
			if obs.AuthorityTier != TierDerivedObservation {
				t.Errorf("expected AuthorityTier=%q, got %q", TierDerivedObservation, obs.AuthorityTier)
			}
			foundValidCritical = true
		}
		if strings.Contains(obs.Content, "Unverified speculative auth issue") {
			if obs.Severity != "info" {
				t.Errorf("missing-PoC high finding must be demoted to 'info', got %q", obs.Severity)
			}
			if obs.Metadata["unverified_poc"] != "true" {
				t.Errorf("expected metadata unverified_poc='true', got %+v", obs.Metadata)
			}
		}
	}
	if !foundValidCritical {
		t.Fatalf("did not find persisted valid critical observation")
	}

	// Re-submitting identical findings with a fresh eval_token must deduplicate via ComputeDedupHash.
	bundle2, err := ev.Prepare(ctx, secLens, cand, false)
	if err != nil {
		t.Fatalf("second Prepare failed: %v", err)
	}
	res2, err := ev.Submit(ctx, bundle2.EvalToken, hostFindings, "sess_sec")
	if err != nil {
		t.Fatalf("second Submit failed: %v", err)
	}
	if res2.AcceptedCount != 0 || res2.DeduplicatedCount != 3 {
		t.Fatalf("expected 0 accepted and 3 deduplicated on idempotent re-submission, got: %+v", res2)
	}
}

func TestHostEval_N8ConcurrentPrepareAndSubmitZeroRaces(t *testing.T) {
	ctx := context.Background()
	mgr := newTestHostEvalBrain(t)
	cfg := DefaultConfig()
	secLens, _ := cfg.GetLens("security-architect")

	ev, err := NewDefaultHostEvaluator(mgr, "concurrent-proj", cfg)
	if err != nil {
		t.Fatalf("NewDefaultHostEvaluator failed: %v", err)
	}

	const numAgents = 8
	const itersPerAgent = 4

	// Phase 1: 8 parallel subagents independently Prepare + Submit distinct candidates concurrently.
	var wg sync.WaitGroup
	errCh := make(chan error, numAgents*itersPerAgent)
	for agentID := 0; agentID < numAgents; agentID++ {
		wg.Add(1)
		go func(aid int) {
			defer wg.Done()
			sessID := fmt.Sprintf("sess_agent_%d", aid)
			for iter := 0; iter < itersPerAgent; iter++ {
				cand := &brain.MemoryNode{
					ID:        fmt.Sprintf("mem_%d_%d", aid, iter),
					SessionID: sessID,
					Category:  "code",
					Content:   fmt.Sprintf(`func (h *Handler) Exec_%d_%d(cmd string) { exec.Command("sh", "-c", cmd) }`, aid, iter),
					CreatedAt: time.Now().UTC(),
				}
				bundle, err := ev.Prepare(ctx, secLens, cand, false)
				if err != nil {
					errCh <- fmt.Errorf("agent %d iter %d prepare: %w", aid, iter, err)
					return
				}
				if bundle.Skipped {
					errCh <- fmt.Errorf("agent %d iter %d unexpectedly skipped", aid, iter)
					return
				}
				payload := fmt.Sprintf(`{"findings":[{"severity":"high","category":"sink_injection","entry_point":"Exec_%d_%d","summary":"Shell injection in Exec_%d_%d","poc":"curl http://localhost:8080/exec_%d_%d?cmd=$(id)"}]}`, aid, iter, aid, iter, aid, iter)
				subRes, err := ev.Submit(ctx, bundle.EvalToken, payload, sessID)
				if err != nil {
					errCh <- fmt.Errorf("agent %d iter %d submit: %w", aid, iter, err)
					return
				}
				if subRes.AcceptedCount != 1 {
					errCh <- fmt.Errorf("agent %d iter %d expected 1 accepted, got %d", aid, iter, subRes.AcceptedCount)
					return
				}
			}
		}(agentID)
	}
	wg.Wait()
	close(errCh)
	for e := range errCh {
		t.Fatalf("N=8 concurrent Prepare/Submit failure: %v", e)
	}

	// Phase 2: 8 goroutines simultaneously race to redeem the EXACT same single-use eval_token.
	raceCand := &brain.MemoryNode{
		ID:        "mem_race_target",
		SessionID: "sess_race",
		Category:  "code",
		Content:   `func (h *Handler) RaceExec(cmd string) { exec.Command("sh", "-c", cmd) }`,
		CreatedAt: time.Now().UTC(),
	}
	raceBundle, err := ev.Prepare(ctx, secLens, raceCand, false)
	if err != nil {
		t.Fatalf("Prepare raceBundle failed: %v", err)
	}
	racePayload := `{"findings":[{"severity":"high","category":"sink_injection","entry_point":"RaceExec","summary":"Race replay test finding","poc":"curl http://localhost:8080/race?cmd=$(id)"}]}`

	var successes atomic.Int32
	var replays atomic.Int32
	var startGate sync.WaitGroup
	startGate.Add(1)
	var raceWG sync.WaitGroup
	for i := 0; i < numAgents; i++ {
		raceWG.Add(1)
		go func() {
			defer raceWG.Done()
			startGate.Wait()
			_, err := ev.Submit(ctx, raceBundle.EvalToken, racePayload, "sess_race")
			if err == nil {
				successes.Add(1)
			} else if errors.Is(err, ErrEvalTokenReplayed) {
				replays.Add(1)
			} else {
				t.Errorf("unexpected error in replay race: %v", err)
			}
		}()
	}
	startGate.Done()
	raceWG.Wait()

	if successes.Load() != 1 || replays.Load() != numAgents-1 {
		t.Fatalf("expected strictly 1 winner and %d replays in N=8 token race, got winners=%d replays=%d",
			numAgents-1, successes.Load(), replays.Load())
	}
}

func TestHostEval_PrefilterSkipsBenignAndForceOverrides(t *testing.T) {
	ctx := context.Background()
	mgr := newTestHostEvalBrain(t)
	cfg := DefaultConfig()
	secLens, _ := cfg.GetLens("security-architect")

	ev, err := NewDefaultHostEvaluator(mgr, "prefilter-proj", cfg)
	if err != nil {
		t.Fatalf("NewDefaultHostEvaluator failed: %v", err)
	}

	benign := &brain.MemoryNode{
		ID:        "mem_benign",
		SessionID: "sess_benign",
		Category:  "code",
		Content:   `// FormatGreeting returns a friendly greeting string.\nfunc FormatGreeting(name string) string { return "Hello, " + name }`,
		CreatedAt: time.Now().UTC(),
	}

	skippedBundle, err := ev.Prepare(ctx, secLens, benign, false)
	if err != nil {
		t.Fatalf("Prepare benign failed: %v", err)
	}
	if !skippedBundle.Skipped || skippedBundle.SkipReason != SkipReasonPrefilterNoSinks {
		t.Fatalf("expected benign candidate skipped with %q, got: %+v", SkipReasonPrefilterNoSinks, skippedBundle)
	}
	if skippedBundle.EvalToken != "" {
		t.Fatalf("skipped bundle must not mint an eval_token")
	}

	// force=true must bypass the pre-filter and produce a valid bundle.
	forcedBundle, err := ev.Prepare(ctx, secLens, benign, true)
	if err != nil {
		t.Fatalf("Prepare forced failed: %v", err)
	}
	if forcedBundle.Skipped || forcedBundle.EvalToken == "" || !strings.Contains(forcedBundle.UserPrompt, "<untrusted_artifact") {
		t.Fatalf("expected forced bundle to prepare XML-fenced prompt and eval_token, got: %+v", forcedBundle)
	}
}

func TestHostEval_RecallsSiblingEndpointsAndProjectContext(t *testing.T) {
	ctx := context.Background()
	mgr := newTestHostEvalBrain(t)
	cfg := DefaultConfig()
	secLens, _ := cfg.GetLens("security-architect")

	// Seed sibling endpoint, architecture ADR, and industry_radar fact.
	_, err := mgr.Remember(ctx, brain.RememberRequest{
		SessionID: "sess_ctx",
		Category:  "code",
		Content:   `func (h *ItemHandler) GetItemHandler(w http.ResponseWriter, r *http.Request) { requireTenantAuth(r); serveItem(w, r) }`,
		Metadata: map[string]string{
			"file_path": "pkg/api/get_item.go",
			"handler":   "GetItemHandler",
		},
	})
	if err != nil {
		t.Fatalf("seed sibling failed: %v", err)
	}

	_, err = mgr.Remember(ctx, brain.RememberRequest{
		SessionID: "sess_ctx",
		Category:  "architecture",
		Content:   "ADR-014: Every HTTP item route handler in pkg/api must verify requireTenantAuth before accessing storage.",
	})
	if err != nil {
		t.Fatalf("seed architecture ADR failed: %v", err)
	}

	_, err = mgr.Remember(ctx, brain.RememberRequest{
		SessionID: "sess_ctx",
		Category:  "industry_radar",
		Content:   "CVE-2026-9999: Missing tenant check on item delete handler enables cross-tenant wipe.",
		Metadata: map[string]string{
			"advisory_id": "CVE-2026-9999",
			"ecosystem":   "go",
			"severity":    "high",
		},
	})
	if err != nil {
		t.Fatalf("seed radar fact failed: %v", err)
	}

	ev, err := NewDefaultHostEvaluator(mgr, "ctx-proj", cfg)
	if err != nil {
		t.Fatalf("NewDefaultHostEvaluator failed: %v", err)
	}

	candidate := &brain.MemoryNode{
		ID:        "mem_delete_item",
		SessionID: "sess_ctx",
		Category:  "code",
		Content:   `func (h *ItemHandler) DeleteItemHandler(w http.ResponseWriter, r *http.Request) { deleteItemByID(r.URL.Query().Get("id")) }`,
		Metadata:  map[string]string{"file_path": "pkg/api/delete_item.go"},
		CreatedAt: time.Now().UTC(),
	}

	bundle, err := ev.Prepare(ctx, secLens, candidate, false)
	if err != nil {
		t.Fatalf("Prepare failed: %v", err)
	}
	if bundle.Skipped {
		t.Fatalf("expected DeleteItemHandler not to be skipped")
	}
	if !strings.Contains(bundle.UserPrompt, "<sibling_endpoints>") || !strings.Contains(bundle.UserPrompt, "GetItemHandler") {
		t.Errorf("expected sibling endpoint recall in UserPrompt, got:\n%s", bundle.UserPrompt)
	}
	if !strings.Contains(bundle.UserPrompt, "<recalled_context>") || !strings.Contains(bundle.UserPrompt, "ADR-014") {
		t.Errorf("expected architecture ADR in <recalled_context>, got:\n%s", bundle.UserPrompt)
	}
	if !strings.Contains(bundle.UserPrompt, "<industry_radar_baseline>") || !strings.Contains(bundle.UserPrompt, "CVE-2026-9999") {
		t.Errorf("expected radar fact in <industry_radar_baseline>, got:\n%s", bundle.UserPrompt)
	}
	if !strings.Contains(bundle.UserPrompt, "<untrusted_artifact") || !strings.Contains(bundle.UserPrompt, "DeleteItemHandler") {
		t.Errorf("expected candidate in <untrusted_artifact>, got:\n%s", bundle.UserPrompt)
	}
	if bundle.SubmitTool != HostEvalSubmitTool {
		t.Errorf("expected submit_tool=%q, got %q", HostEvalSubmitTool, bundle.SubmitTool)
	}
}
