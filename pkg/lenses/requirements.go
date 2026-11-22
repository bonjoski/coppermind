package lenses

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/capsule"
	"github.com/bonjoski/coppermind/pkg/embedding"
	"github.com/bonjoski/coppermind/pkg/security"
)

// RequirementsLens maps a raw story/PRD and optional 5-Q trigger flags to <= 3 sprint-ready criteria.
type RequirementsLens interface {
	SuggestCriteria(storyText string, triggers []capsule.TriggerFlag, maxCriteria int) ([]capsule.AbuseCaseCriterion, error)
}

type indexedRequirementCard struct {
	rec           capsule.RequirementsCriterionRecord
	triggerSet    map[capsule.TriggerFlag]struct{}
	keywordsLower []string
	keywordTokens []map[string]struct{}
	cardTokens    map[string]struct{}
}

// SQLiteRequirementsLens implements RequirementsLens lock-free over SQLite WAL (with zero-config
// fallback to the embedded curated 10-card PO starter catalog). It is strictly read-only and ephemeral:
// raw story inputs are NFKC-sanitized in memory, never echoed into output, and never persisted to SQLite.
type SQLiteRequirementsLens struct {
	store    capsule.SQLiteAccessor
	embedder brain.Embedder

	cacheMu      sync.RWMutex
	cachedLoaded bool
	cachedGen    uint64
	cachedCards  []indexedRequirementCard
}

// NewSQLiteRequirementsLens creates a read-only requirements lens backed by SQLite WAL with
// built-in curated defaults when no custom requirements capsule has been imported.
func NewSQLiteRequirementsLens(store brain.MemoryStore, embedder brain.Embedder) *SQLiteRequirementsLens {
	var accessor capsule.SQLiteAccessor
	if store != nil {
		if a, ok := store.(capsule.SQLiteAccessor); ok {
			accessor = a
		}
	}
	if embedder == nil {
		embedder = embedding.NewLocalHashEmbedder(128)
	}
	return &SQLiteRequirementsLens{
		store:    accessor,
		embedder: embedder,
	}
}

func indexRequirementRecords(records []capsule.RequirementsCriterionRecord) []indexedRequirementCard {
	indexed := make([]indexedRequirementCard, 0, len(records))
	for _, rec := range records {
		// Defense-in-depth: never index a record whose verify_cmd fails allowlist or contains HTML/XSS.
		if err := capsule.ValidateVerifyCmd(rec.Criterion.VerifyCmd); err != nil {
			continue
		}
		if capsule.HasUnsafeHTMLOrXSS(rec.Criterion.PlainTitle) ||
			capsule.HasUnsafeHTMLOrXSS(rec.Criterion.Given) ||
			capsule.HasUnsafeHTMLOrXSS(rec.Criterion.When) ||
			capsule.HasUnsafeHTMLOrXSS(rec.Criterion.Then) ||
			capsule.HasUnsafeHTMLOrXSS(rec.Criterion.WhyOneLiner) {
			continue
		}

		c := rec.Criterion
		trigSet := make(map[capsule.TriggerFlag]struct{}, len(c.Triggers))
		for _, t := range c.Triggers {
			trigSet[t] = struct{}{}
		}
		kwLower := make([]string, len(c.Keywords))
		kwToks := make([]map[string]struct{}, len(c.Keywords))
		for j, kw := range c.Keywords {
			kl := strings.ToLower(strings.TrimSpace(kw))
			kwLower[j] = kl
			if strings.Contains(kl, " ") {
				kwToks[j] = tokenizeMentorText(kl)
			}
		}
		cardToks := tokenizeMentorText(strings.ToLower(
			c.PlainTitle + " " + c.Given + " " + c.When + " " + c.Then + " " + c.WhyOneLiner + " " + strings.Join(c.Keywords, " "),
		))
		indexed = append(indexed, indexedRequirementCard{
			rec:           rec,
			triggerSet:    trigSet,
			keywordsLower: kwLower,
			keywordTokens: kwToks,
			cardTokens:    cardToks,
		})
	}
	return indexed
}

func (l *SQLiteRequirementsLens) loadIndexedCriteria(ctx context.Context) ([]indexedRequirementCard, error) {
	gen := capsule.RequirementsWriteGeneration()

	l.cacheMu.RLock()
	if l.cachedLoaded && l.cachedGen == gen {
		cards := l.cachedCards
		l.cacheMu.RUnlock()
		return cards, nil
	}
	l.cacheMu.RUnlock()

	var (
		records []capsule.RequirementsCriterionRecord
		err     error
	)
	if l.store != nil {
		records, err = capsule.LoadAllRequirementsCriteria(ctx, l.store)
		if err != nil {
			return nil, err
		}
	}
	if len(records) == 0 {
		records, err = capsule.DefaultRequirementsRecords()
		if err != nil {
			return nil, fmt.Errorf("failed loading built-in requirements catalog: %w", err)
		}
	}

	indexed := indexRequirementRecords(records)

	l.cacheMu.Lock()
	l.cachedCards = indexed
	l.cachedGen = gen
	l.cachedLoaded = true
	l.cacheMu.Unlock()

	return indexed, nil
}

// SuggestCriteria matches raw story text and optional 5-Q trigger flags against verified criteria,
// returning at most maxCriteria (hard ceiling: 3) sprint-ready criteria within <= 180 tokens total.
func (l *SQLiteRequirementsLens) SuggestCriteria(storyText string, triggers []capsule.TriggerFlag, maxCriteria int) ([]capsule.AbuseCaseCriterion, error) {
	return l.SuggestCriteriaContext(context.Background(), storyText, triggers, maxCriteria)
}

// SuggestCriteriaContext executes ephemeral, read-only deterministic matching over SQLite WAL or defaults.
func (l *SQLiteRequirementsLens) SuggestCriteriaContext(ctx context.Context, storyText string, triggers []capsule.TriggerFlag, maxCriteria int) ([]capsule.AbuseCaseCriterion, error) {
	if len(storyText) > capsule.MaxRequirementsStoryBytes {
		return nil, fmt.Errorf("%w: story text exceeds %d bytes", capsule.ErrRequirementsStoryTooLarge, capsule.MaxRequirementsStoryBytes)
	}

	for _, t := range triggers {
		if !capsule.ValidTriggerFlag(t) {
			return nil, fmt.Errorf("%w: unknown trigger flag %q", capsule.ErrRequirementsValidation, t)
		}
	}

	// Sanitize untrusted story text purely in-memory via NFKC + zero-width/XML stripping.
	// Raw story text is NEVER persisted and NEVER interpolated into returned criteria.
	sanitizedStory, _ := security.SanitizeXMLDelimiters(storyText)
	sanitizedStory = strings.TrimSpace(capsule.StripControlAndANSI(sanitizedStory))

	if sanitizedStory == "" && len(triggers) == 0 {
		return []capsule.AbuseCaseCriterion{}, nil
	}

	if maxCriteria <= 0 || maxCriteria > capsule.MaxRequirementsCriteria {
		maxCriteria = capsule.MaxRequirementsCriteria
	}

	indexed, err := l.loadIndexedCriteria(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load requirements criteria: %w", err)
	}
	if len(indexed) == 0 {
		return []capsule.AbuseCaseCriterion{}, nil
	}

	storyLower := strings.ToLower(sanitizedStory)
	storyTokens := tokenizeMentorText(storyLower)

	var storyVec []float32
	if sanitizedStory != "" {
		storyVec, err = l.embedder.Embed(ctx, sanitizedStory)
		if err != nil {
			storyVec, _ = embedding.NewLocalHashEmbedder(128).Embed(ctx, sanitizedStory)
		}
	}

	type scoredCriterion struct {
		crit  capsule.AbuseCaseCriterion
		score float32
	}

	hasTriggerFilter := len(triggers) > 0
	scored := make([]scoredCriterion, 0, len(indexed))

	for i := range indexed {
		item := &indexed[i]
		trigHits := 0
		if hasTriggerFilter {
			for _, t := range triggers {
				if _, ok := item.triggerSet[t]; ok {
					trigHits++
				}
			}
			// When explicit 5-Q trigger flags are provided, filter strictly to matching trigger flags.
			if trigHits == 0 {
				continue
			}
		}

		score := scoreIndexedRequirement(item, trigHits, storyLower, storyTokens, storyVec)
		if !hasTriggerFilter && score <= 0.0 {
			continue
		}
		scored = append(scored, scoredCriterion{
			crit:  cloneSanitizedCriterion(item.rec.Criterion),
			score: score,
		})
	}

	sort.Slice(scored, func(i, j int) bool {
		if scored[i].score == scored[j].score {
			return scored[i].crit.ID < scored[j].crit.ID
		}
		return scored[i].score > scored[j].score
	})

	// When multiple explicit triggers were checked, promote trigger diversity so at least one
	// top criterion per checked trigger appears in the top <= 3 results when available.
	selected := make([]capsule.AbuseCaseCriterion, 0, maxCriteria)
	if len(triggers) > 1 && len(scored) > 1 {
		used := make([]bool, len(scored))
		for _, wantTrig := range triggers {
			if len(selected) >= maxCriteria {
				break
			}
			for idx, sc := range scored {
				if used[idx] {
					continue
				}
				if criterionHasTrigger(sc.crit, wantTrig) {
					selected = append(selected, sc.crit)
					used[idx] = true
					break
				}
			}
		}
		for idx, sc := range scored {
			if len(selected) >= maxCriteria {
				break
			}
			if !used[idx] {
				selected = append(selected, sc.crit)
				used[idx] = true
			}
		}
	} else {
		limit := maxCriteria
		if len(scored) < limit {
			limit = len(scored)
		}
		for i := 0; i < limit; i++ {
			selected = append(selected, scored[i].crit)
		}
	}

	// Enforce strict <= 180 total token ceiling on default Markdown output.
	for len(selected) > 1 && EstimateTokens(FormatRequirementsMarkdown(selected, false)) > capsule.MaxRequirementsTotalTokens {
		selected = selected[:len(selected)-1]
	}

	return selected, nil
}

func criterionHasTrigger(c capsule.AbuseCaseCriterion, want capsule.TriggerFlag) bool {
	for _, t := range c.Triggers {
		if t == want {
			return true
		}
	}
	return false
}

func scoreIndexedRequirement(item *indexedRequirementCard, trigHits int, storyLower string, storyTokens map[string]struct{}, storyVec []float32) float32 {
	var score float32
	if trigHits > 0 {
		score += 1.5 * float32(trigHits)
	}

	var kwScore float32
	if storyLower != "" {
		for j, kw := range item.keywordsLower {
			if kw == "" {
				continue
			}
			if strings.Contains(kw, " ") {
				if strings.Contains(storyLower, kw) {
					kwScore += 0.65
					continue
				}
				kwToks := item.keywordTokens[j]
				if len(kwToks) > 1 {
					hits := 0
					for tok := range kwToks {
						if _, ok := storyTokens[tok]; ok {
							hits++
						}
					}
					if hits == len(kwToks) {
						kwScore += 0.45
					} else if hits > 0 {
						kwScore += 0.15 * float32(hits) / float32(len(kwToks))
					}
				}
			} else {
				if _, ok := storyTokens[kw]; ok {
					kwScore += 0.50
				}
			}
		}
		if kwScore > 1.8 {
			kwScore = 1.8
		}
	}

	var overlapScore float32
	if len(storyTokens) > 0 && len(item.cardTokens) > 0 {
		overlap := 0
		for tok := range storyTokens {
			if _, ok := item.cardTokens[tok]; ok {
				overlap++
			}
		}
		if overlap > 0 {
			overlapScore = 0.40 * float32(overlap) / float32(len(storyTokens))
		}
	}

	var cosine float32
	if len(storyVec) > 0 && len(item.rec.Vector) == len(storyVec) {
		cosine = embedding.CosineSimilarity(storyVec, item.rec.Vector)
		if cosine < 0 {
			cosine = 0
		}
	}

	// Suppress unrelated noise when no explicit triggers were passed and story has no real match.
	if trigHits == 0 && kwScore == 0 && overlapScore < 0.08 && cosine < 0.42 {
		return 0
	}

	return score + kwScore + overlapScore + 0.30*cosine
}

func cloneSanitizedCriterion(c capsule.AbuseCaseCriterion) capsule.AbuseCaseCriterion {
	trigs := make([]capsule.TriggerFlag, len(c.Triggers))
	copy(trigs, c.Triggers)
	kws := make([]string, len(c.Keywords))
	copy(kws, c.Keywords)
	return capsule.AbuseCaseCriterion{
		ID:          capsule.StripControlAndANSI(strings.TrimSpace(c.ID)),
		Triggers:    trigs,
		Keywords:    kws,
		PlainTitle:  capsule.StripControlAndANSI(strings.TrimSpace(c.PlainTitle)),
		Given:       capsule.StripControlAndANSI(strings.TrimSpace(c.Given)),
		When:        capsule.StripControlAndANSI(strings.TrimSpace(c.When)),
		Then:        capsule.StripControlAndANSI(strings.TrimSpace(c.Then)),
		WhyOneLiner: capsule.StripControlAndANSI(strings.TrimSpace(c.WhyOneLiner)),
		VerifyCmd:   capsule.StripControlAndANSI(strings.TrimSpace(c.VerifyCmd)),
		KataRef:     capsule.StripControlAndANSI(strings.TrimSpace(c.KataRef)),
	}
}

// FormatRequirementsMarkdown formats <= 3 AbuseCaseCriteria into calm, sprint-ready Markdown
// ready to paste into GitHub Issues, Jira tickets, or Linear stories.
func FormatRequirementsMarkdown(criteria []capsule.AbuseCaseCriterion, includeWhy bool) string {
	if len(criteria) == 0 {
		return "No blast-radius triggers matched — zero security ceremony required."
	}
	if len(criteria) > capsule.MaxRequirementsCriteria {
		criteria = criteria[:capsule.MaxRequirementsCriteria]
	}

	var sb strings.Builder
	sb.WriteString("### Safety Acceptance Criteria\n")
	for i, c := range criteria {
		clean := cloneSanitizedCriterion(c)
		sb.WriteString(fmt.Sprintf("%d. **%s**\n", i+1, clean.PlainTitle))
		sb.WriteString(fmt.Sprintf("  - **Given** %s\n", clean.Given))
		sb.WriteString(fmt.Sprintf("  - **When** %s\n", clean.When))
		sb.WriteString(fmt.Sprintf("  - **Then** %s\n", clean.Then))
		sb.WriteString(fmt.Sprintf("  - *Verify:* `%s`", clean.VerifyCmd))
		if includeWhy {
			sb.WriteString(fmt.Sprintf("\n  - *Why:* %s", clean.WhyOneLiner))
			if clean.KataRef != "" {
				sb.WriteString(fmt.Sprintf("\n  - *Kata:* `aegisbox learn %s`", clean.KataRef))
			}
		}
		if i < len(criteria)-1 {
			sb.WriteString("\n")
		}
	}
	return sb.String()
}

// RequirementsJSONPayload is the machine-readable JSON response emitted by --json.
type RequirementsJSONPayload struct {
	Count           int                          `json:"count"`
	EstimatedTokens int                          `json:"estimated_tokens"`
	Criteria        []capsule.AbuseCaseCriterion `json:"criteria"`
}

// FormatRequirementsJSON formats criteria as deterministic, pretty-printed JSON.
func FormatRequirementsJSON(criteria []capsule.AbuseCaseCriterion, includeWhy bool) (string, error) {
	if len(criteria) > capsule.MaxRequirementsCriteria {
		criteria = criteria[:capsule.MaxRequirementsCriteria]
	}
	out := make([]capsule.AbuseCaseCriterion, 0, len(criteria))
	for _, c := range criteria {
		out = append(out, cloneSanitizedCriterion(c))
	}
	payload := RequirementsJSONPayload{
		Count:           len(out),
		EstimatedTokens: EstimateTokens(FormatRequirementsMarkdown(out, includeWhy)),
		Criteria:        out,
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}
