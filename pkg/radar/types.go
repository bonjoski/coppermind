package radar

import (
	"context"
	"time"
)

// Severity levels for radar facts.
const (
	SeverityInfo     = "info"
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// SeverityRank converts severity string to a comparable integer score.
func SeverityRank(sev string) int {
	switch sev {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 1
	}
}

// Categories for radar facts.
const (
	CategoryDeprecation     = "deprecation"
	CategoryStandard        = "standard"
	CategoryVulnerability   = "vulnerability"
	CategoryExploitPrimitive = "exploit_primitive"
)

// RadarFact represents a structured, sanitized piece of temporal industry intelligence.
type RadarFact struct {
	ID                     string `json:"id"`
	FeedID                 string `json:"feed_id"`
	Ecosystem              string `json:"ecosystem"` // "golang", "rust", "jvm", "dotnet", "node-typescript", "python", "security-core", "cloud-arch"
	Technology             string `json:"technology"`
	Category               string `json:"category"` // "deprecation", "standard", "vulnerability", "exploit_primitive"
	AdvisoryID             string `json:"advisory_id,omitempty"`
	Severity               string `json:"severity"`
	Summary                string `json:"summary"`
	RecommendedAlternative string `json:"recommended_alternative,omitempty"`
	Evidence               string `json:"evidence,omitempty"`
	EffectiveDate          string `json:"effective_date"`
	ProvenanceURL          string `json:"provenance_url"`
	AuthorityTier          string `json:"authority_tier"`
	CreatedAt              time.Time `json:"created_at"`
}

// RawItem represents an unparsed upstream article, advisory, or bulletin before distillation.
type RawItem struct {
	FeedID      string    `json:"feed_id"`
	ExternalID  string    `json:"external_id"`
	Title       string    `json:"title"`
	RawBody     string    `json:"raw_body"`
	URL         string    `json:"url"`
	PublishedAt time.Time `json:"published_at"`
}

// FeedConfig defines the configuration for an individual upstream radar source.
type FeedConfig struct {
	ID                string `yaml:"id" json:"id"`
	Name              string `yaml:"name" json:"name"`
	Ecosystem         string `yaml:"ecosystem" json:"ecosystem"`
	Adapter           string `yaml:"adapter" json:"adapter"` // "rss", "osv-stream", "cisa-kev", "github-advisories", "json-api", "static"
	URL               string `yaml:"url" json:"url"`
	TargetRepo        string `yaml:"target_repo,omitempty" json:"target_repo,omitempty"`
	SeverityThreshold string `yaml:"severity_threshold,omitempty" json:"severity_threshold,omitempty"`
	Enabled           bool   `yaml:"enabled" json:"enabled"`
	AuthSecretRef     string `yaml:"auth_secret_ref,omitempty" json:"auth_secret_ref,omitempty"`
}

// FeedAdapter defines the contract for fetching upstream data from an external feed.
type FeedAdapter interface {
	Type() string
	Fetch(ctx context.Context, config FeedConfig) ([]RawItem, error)
}
