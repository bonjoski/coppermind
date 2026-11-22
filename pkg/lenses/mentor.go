package lenses

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"unicode"

	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/capsule"
	"github.com/bonjoski/coppermind/pkg/embedding"
)

const (
	// MaxMentorNudgeCards is the hard ceiling on cards returned per passive mentor recall.
	MaxMentorNudgeCards = 2

	// MaxMentorNudgeTokens is the strict per-nudge token budget preventing prompt bloat.
	MaxMentorNudgeTokens = 120
)

// MentorLens formats retrieved MentorCards into strict token-budgeted passive nudges.
type MentorLens interface {
	// Match returns at most maxCards (hard ceiling: 2) relevant cards for an ideation prompt.
	Match(query string, detectedSDKs []string, maxCards int) ([]MentorNudge, error)
}

// MentorNudge is a compact, non-blocking security power-steering recommendation
// strictly budgeted to <= 120 tokens per card.
type MentorNudge struct {
	CardID        string  `json:"card_id"`
	CapsuleRef    string  `json:"capsule_ref,omitempty"`
	MerklePrefix  string  `json:"merkle_prefix,omitempty"`
	AuthorityTier string  `json:"authority_tier,omitempty"`
	Provenance    string  `json:"provenance,omitempty"`
	Title         string  `json:"title,omitempty"`
	SecureDefault string  `json:"secure_default"`
	WhyOneLiner   string  `json:"why_one_liner"`
	Analogy       string  `json:"analogy,omitempty"`
	KataCommand   string  `json:"kata_command,omitempty"`
	CWEOrOWASP    string  `json:"cwe_or_owasp,omitempty"`
	Score         float32 `json:"score,omitempty"`
}

type indexedMentorCard struct {
	rec             capsule.MentorCardRecord
	triggersLower   []string
	triggerTokens   []map[string]struct{}
	sdkHaystack     string
	cardTokens      map[string]struct{}
}

// SQLiteMentorLens implements MentorLens against Coppermind's local SQLite WAL mentor_cards table
// with a generation-invalidated read-through cache for sub-millisecond N=8 lock-free recall.
type SQLiteMentorLens struct {
	store    capsule.SQLiteAccessor
	embedder brain.Embedder

	cacheMu      sync.RWMutex
	cachedLoaded bool
	cachedGen    uint64
	cachedCards  []indexedMentorCard
}

// NewSQLiteMentorLens creates a lock-free WAL mentor lens backed by the active store.
// If store does not implement capsule.SQLiteAccessor, Match returns an empty slice safely.
func NewSQLiteMentorLens(store brain.MemoryStore, embedder brain.Embedder) *SQLiteMentorLens {
	var accessor capsule.SQLiteAccessor
	if store != nil {
		if a, ok := store.(capsule.SQLiteAccessor); ok {
			accessor = a
		}
	}
	if embedder == nil {
		embedder = embedding.NewLocalHashEmbedder(128)
	}
	return &SQLiteMentorLens{
		store:    accessor,
		embedder: embedder,
	}
}

func (l *SQLiteMentorLens) loadIndexedCards(ctx context.Context) ([]indexedMentorCard, error) {
	gen := capsule.MentorWriteGeneration()

	l.cacheMu.RLock()
	if l.cachedLoaded && l.cachedGen == gen {
		cards := l.cachedCards
		l.cacheMu.RUnlock()
		return cards, nil
	}
	l.cacheMu.RUnlock()

	// Double-checked write lock eliminates N=8 cold-start thundering-herd SQLite scans.
	l.cacheMu.Lock()
	defer l.cacheMu.Unlock()

	gen = capsule.MentorWriteGeneration()
	if l.cachedLoaded && l.cachedGen == gen {
		return l.cachedCards, nil
	}

	var (
		records []capsule.MentorCardRecord
		err     error
	)
	if l.store != nil {
		records, err = capsule.LoadAllMentorCards(ctx, l.store)
		if err != nil {
			return nil, err
		}
	}
	if len(records) == 0 {
		records, err = capsule.DefaultMentorCardRecords()
		if err != nil {
			return nil, fmt.Errorf("failed loading built-in mentor defaults: %w", err)
		}
	}

	indexed := make([]indexedMentorCard, len(records))
	for i, rec := range records {
		c := rec.Card
		tLower := make([]string, len(c.Triggers))
		tToks := make([]map[string]struct{}, len(c.Triggers))
		for j, trig := range c.Triggers {
			tl := strings.ToLower(strings.TrimSpace(trig))
			tLower[j] = tl
			if strings.Contains(tl, " ") {
				tToks[j] = tokenizeMentorText(tl)
			}
		}
		indexed[i] = indexedMentorCard{
			rec:           rec,
			triggersLower: tLower,
			triggerTokens: tToks,
			sdkHaystack:   strings.ToLower(c.Domain + " " + c.Title + " " + strings.Join(c.Triggers, " ") + " " + c.SecureDefault),
			cardTokens: tokenizeMentorText(strings.ToLower(
				c.Domain + " " + c.Title + " " + c.DeterministicEq + " " + c.SecureDefault + " " + c.WhyOneLiner + " " + c.CWEOrOWASP,
			)),
		}
	}

	l.cachedCards = indexed
	l.cachedGen = gen
	l.cachedLoaded = true

	return indexed, nil
}

// Match returns at most maxCards (hard ceiling: 2) relevant security mentor nudges for query and detectedSDKs.
func (l *SQLiteMentorLens) Match(query string, detectedSDKs []string, maxCards int) ([]MentorNudge, error) {
	return l.MatchContext(context.Background(), query, detectedSDKs, maxCards)
}

// MatchContext executes hybrid trigger/keyword + cosine semantic matching lock-free over SQLite WAL
// (automatically falling back to the 18 embedded curated v1.0 mentor cards when mentor_cards is empty).
func (l *SQLiteMentorLens) MatchContext(ctx context.Context, query string, detectedSDKs []string, maxCards int) ([]MentorNudge, error) {
	if strings.TrimSpace(query) == "" && len(detectedSDKs) == 0 {
		return nil, fmt.Errorf("mentor lens requires a non-empty query or detected SDKs")
	}
	if maxCards <= 0 || maxCards > MaxMentorNudgeCards {
		maxCards = MaxMentorNudgeCards
	}

	indexed, err := l.loadIndexedCards(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load mentor cards: %w", err)
	}
	if len(indexed) == 0 {
		return nil, nil
	}

	combinedQuery := strings.TrimSpace(query + " " + strings.Join(detectedSDKs, " "))
	queryLower := strings.ToLower(combinedQuery)
	queryTokens := tokenizeMentorText(queryLower)
	sdkLower := make([]string, 0, len(detectedSDKs))
	for _, sdk := range detectedSDKs {
		if s := strings.ToLower(strings.TrimSpace(sdk)); s != "" {
			sdkLower = append(sdkLower, s)
		}
	}

	queryVec, err := l.embedder.Embed(ctx, combinedQuery)
	if err != nil {
		// Fall back cleanly to local hash embedder so recall never blocks on network/LLM availability
		queryVec, _ = embedding.NewLocalHashEmbedder(128).Embed(ctx, combinedQuery)
	}

	type scoredCard struct {
		rec   capsule.MentorCardRecord
		score float32
	}

	scored := make([]scoredCard, 0, len(indexed))
	for i := range indexed {
		score := scoreIndexedMentorCard(&indexed[i], queryLower, queryTokens, sdkLower, queryVec)
		if score <= 0.0 {
			continue
		}
		scored = append(scored, scoredCard{rec: indexed[i].rec, score: score})
	}

	sort.Slice(scored, func(i, j int) bool {
		if scored[i].score == scored[j].score {
			return scored[i].rec.Card.ID < scored[j].rec.Card.ID
		}
		return scored[i].score > scored[j].score
	})

	if len(scored) > maxCards {
		scored = scored[:maxCards]
	}

	nudges := make([]MentorNudge, 0, len(scored))
	for _, s := range scored {
		nudges = append(nudges, buildBudgetedNudge(s.rec, s.score))
	}
	return nudges, nil
}

func scoreIndexedMentorCard(item *indexedMentorCard, queryLower string, queryTokens map[string]struct{}, sdkLower []string, queryVec []float32) float32 {
	var triggerScore float32
	for j, tLower := range item.triggersLower {
		if tLower == "" {
			continue
		}
		if strings.Contains(queryLower, tLower) {
			if strings.Contains(tLower, " ") {
				triggerScore += 0.55 // Multi-word phrase trigger hit
			} else {
				triggerScore += 0.40
			}
			continue
		}
		// Partial token overlap on multi-word triggers
		trigTokens := item.triggerTokens[j]
		if len(trigTokens) > 1 {
			hits := 0
			for tok := range trigTokens {
				if _, ok := queryTokens[tok]; ok {
					hits++
				}
			}
			if hits > 0 {
				triggerScore += 0.25 * float32(hits) / float32(len(trigTokens))
			}
		}
	}
	if triggerScore > 1.2 {
		triggerScore = 1.2
	}

	var sdkScore float32
	if len(sdkLower) > 0 {
		for _, sdk := range sdkLower {
			if strings.Contains(item.sdkHaystack, sdk) {
				sdkScore += 0.30
			}
		}
		if sdkScore > 0.6 {
			sdkScore = 0.6
		}
	}

	// Keyword overlap across pre-tokenized card metadata
	var keywordScore float32
	if len(queryTokens) > 0 && len(item.cardTokens) > 0 {
		overlap := 0
		for tok := range queryTokens {
			if _, ok := item.cardTokens[tok]; ok {
				overlap++
			}
		}
		if overlap > 0 {
			keywordScore = 0.45 * float32(overlap) / float32(len(queryTokens))
		}
	}

	var cosine float32
	if len(queryVec) > 0 && len(item.rec.Vector) == len(queryVec) {
		cosine = embedding.CosineSimilarity(queryVec, item.rec.Vector)
		if cosine < 0 {
			cosine = 0
		}
	}

	// Suppress unrelated noise when neither triggers nor keywords match and cosine similarity is weak
	if triggerScore == 0 && sdkScore == 0 && keywordScore == 0 && cosine < 0.30 {
		return 0
	}

	return triggerScore + sdkScore + keywordScore + 0.35*cosine
}

func buildBudgetedNudge(rec capsule.MentorCardRecord, score float32) MentorNudge {
	card := rec.Card
	kataCmd := ""
	if strings.TrimSpace(card.KataRef) != "" {
		kataCmd = "aegisbox learn " + strings.TrimSpace(card.KataRef)
	}

	nudge := MentorNudge{
		CardID:        card.ID,
		CapsuleRef:    fmt.Sprintf("%s@%s", rec.CapsuleName, rec.CapsuleVersion),
		MerklePrefix:  rec.MerklePrefix,
		AuthorityTier: capsule.TierMentorCapsule,
		Provenance:    rec.Provenance,
		Title:         card.Title,
		SecureDefault: strings.TrimSpace(card.SecureDefault),
		WhyOneLiner:   strings.TrimSpace(card.WhyOneLiner),
		Analogy:       strings.TrimSpace(card.DeterministicEq),
		KataCommand:   kataCmd,
		CWEOrOWASP:    strings.TrimSpace(card.CWEOrOWASP),
		Score:         score,
	}

	// Enforce strict <= 120 token budget per rendered nudge by trimming optional fields first if ever needed.
	if EstimateTokens(FormatMentorNudge(nudge)) > MaxMentorNudgeTokens {
		nudge.Analogy = ""
	}
	if EstimateTokens(FormatMentorNudge(nudge)) > MaxMentorNudgeTokens {
		nudge.KataCommand = ""
	}
	if EstimateTokens(FormatMentorNudge(nudge)) > MaxMentorNudgeTokens {
		nudge.WhyOneLiner = truncateToTokenBudget(nudge.WhyOneLiner, 40)
		nudge.SecureDefault = truncateToTokenBudget(nudge.SecureDefault, 40)
	}

	return nudge
}

// EstimateTokens estimates LLM token count conservatively as max(word_count, ceil(rune_count/4)).
func EstimateTokens(text string) int {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return 0
	}
	words := len(strings.Fields(trimmed))
	charEst := (len([]rune(trimmed)) + 3) / 4
	if charEst > words {
		return charEst
	}
	return words
}

func truncateToTokenBudget(text string, maxTokens int) string {
	words := strings.Fields(text)
	if len(words) <= maxTokens && EstimateTokens(text) <= maxTokens {
		return text
	}
	if len(words) > maxTokens {
		words = words[:maxTokens]
	}
	out := strings.Join(words, " ")
	maxRunes := maxTokens * 4
	runes := []rune(out)
	if len(runes) > maxRunes && maxRunes > 3 {
		out = string(runes[:maxRunes-3]) + "..."
	}
	return out
}

// FormatMentorNudge renders a single compact passive nudge strictly within <= 120 tokens.
func FormatMentorNudge(n MentorNudge) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[%s | %s | %s#%s]\n", n.CardID, n.AuthorityTier, n.CapsuleRef, n.MerklePrefix))
	sb.WriteString(fmt.Sprintf("Default: %s\n", n.SecureDefault))
	sb.WriteString(fmt.Sprintf("Why: %s", n.WhyOneLiner))
	if n.Analogy != "" {
		sb.WriteString(fmt.Sprintf("\nAnalogy: %s", n.Analogy))
	}
	if n.KataCommand != "" {
		sb.WriteString(fmt.Sprintf("\nKata: `%s`", n.KataCommand))
	}
	return sb.String()
}

// FormatMentorNudges formats up to 2 mentor nudges for MCP or CLI passive display.
func FormatMentorNudges(nudges []MentorNudge) string {
	if len(nudges) == 0 {
		return "No matching security mentor nudges found."
	}
	if len(nudges) > MaxMentorNudgeCards {
		nudges = nudges[:MaxMentorNudgeCards]
	}
	var sb strings.Builder
	for i, n := range nudges {
		if i > 0 {
			sb.WriteString("\n\n")
		}
		sb.WriteString(FormatMentorNudge(n))
	}
	return sb.String()
}

var mentorStopWords = map[string]struct{}{
	"a": {}, "an": {}, "the": {}, "and": {}, "or": {}, "to": {}, "of": {}, "in": {}, "on": {},
	"for": {}, "with": {}, "by": {}, "is": {}, "are": {}, "be": {}, "add": {}, "new": {},
	"how": {}, "use": {}, "from": {}, "into": {}, "that": {}, "this": {}, "your": {},
}

func tokenizeMentorText(s string) map[string]struct{} {
	tokens := make(map[string]struct{})
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 1 {
			w := cur.String()
			if _, stop := mentorStopWords[w]; !stop {
				tokens[w] = struct{}{}
			}
		}
		cur.Reset()
	}
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-' {
			cur.WriteRune(unicode.ToLower(r))
		} else {
			flush()
		}
	}
	flush()
	return tokens
}
