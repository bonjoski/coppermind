package radar

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// RadarSettings holds operational settings for the radar subsystem.
type RadarSettings struct {
	Enabled               bool   `yaml:"enabled" json:"enabled"` // OFF by default
	SyncInterval          string `yaml:"sync_interval" json:"sync_interval"`
	MaxFactsPerFeed       int    `yaml:"max_facts_per_feed" json:"max_facts_per_feed"`
	AutoDetectEcosystems  bool   `yaml:"auto_detect_ecosystems" json:"auto_detect_ecosystems"`
	QuarantineUnverified  bool   `yaml:"quarantine_unverified" json:"quarantine_unverified"`
	MinConfidence         string `yaml:"min_confidence" json:"min_confidence"`
	MinSeverity           string `yaml:"min_severity" json:"min_severity"`
	FactTTL               string `yaml:"fact_ttl" json:"fact_ttl"`
	CapsulePath           string `yaml:"capsule_path,omitempty" json:"capsule_path,omitempty"`
	CapsuleDir            string `yaml:"capsule_dir,omitempty" json:"capsule_dir,omitempty"`
	DisableAmbientCapsules bool  `yaml:"disable_ambient_capsules,omitempty" json:"disable_ambient_capsules,omitempty"`
}

// RadarConfig holds the declarative radar configuration.
type RadarConfig struct {
	Version      string        `yaml:"version" json:"version"`
	Settings     RadarSettings `yaml:"settings" json:"settings"`
	EnabledPacks []string      `yaml:"enabled_packs" json:"enabled_packs"`
	CustomFeeds  []FeedConfig  `yaml:"custom_feeds" json:"custom_feeds"`
}

// GetSyncInterval parsed as time.Duration, defaulting to 24h.
func (c *RadarConfig) GetSyncInterval() time.Duration {
	d, err := time.ParseDuration(c.Settings.SyncInterval)
	if err != nil || d <= 0 {
		return 24 * time.Hour
	}
	return d
}

// CuratedPackFeeds maps built-in ecosystem packs to their canonical curated feeds.
var CuratedPackFeeds = map[string][]FeedConfig{
	"go-rust": {
		{
			ID:        "go-release-notes",
			Name:      "Go Language Release Notes & Security",
			Ecosystem: "golang",
			Adapter:   "rss",
			URL:       "https://go.dev/blog/feed.atom",
			Enabled:   true,
		},
		{
			ID:        "rust-security-advisories",
			Name:      "RustSec Advisory Database",
			Ecosystem: "rust",
			Adapter:   "osv-stream",
			URL:       "https://api.osv.dev/v1/query",
			Enabled:   true,
		},
	},
	"security-core": {
		{
			ID:                "cisa-kev",
			Name:              "CISA Known Exploited Vulnerabilities",
			Ecosystem:         "security-core",
			Adapter:           "cisa-kev",
			URL:               "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
			SeverityThreshold: "high",
			Enabled:           true,
		},
		{
			ID:                "osv-critical-alerts",
			Name:              "OSV Critical Ecosystem Advisories",
			Ecosystem:         "security-core",
			Adapter:           "osv-stream",
			URL:               "https://api.osv.dev/v1/query",
			SeverityThreshold: "high",
			Enabled:           true,
		},
	},
	"cloud-arch": {
		{
			ID:        "ietf-rfc-standards",
			Name:      "IETF Standards & Modern Protocols",
			Ecosystem: "cloud-arch",
			Adapter:   "rss",
			URL:       "https://www.rfc-editor.org/rfc-index.xml",
			Enabled:   true,
		},
	},
	"jvm": {
		{
			ID:        "openjdk-jeps",
			Name:      "OpenJDK Enhancements (JEPs)",
			Ecosystem: "jvm",
			Adapter:   "rss",
			URL:       "https://openjdk.org/jeps/rss.xml",
			Enabled:   true,
		},
		{
			ID:                "spring-security-advisories",
			Name:              "Spring Projects Security Advisories",
			Ecosystem:         "jvm",
			Adapter:           "osv-stream",
			URL:               "https://api.osv.dev/v1/query",
			SeverityThreshold: "medium",
			Enabled:           true,
		},
	},
	"node-typescript": {
		{
			ID:        "nodejs-releases",
			Name:      "Node.js Releases & Security Bulletins",
			Ecosystem: "node-typescript",
			Adapter:   "rss",
			URL:       "https://nodejs.org/en/feed/blog.xml",
			Enabled:   true,
		},
		{
			ID:                "npm-audit-osv",
			Name:              "NPM / JS Security Advisories",
			Ecosystem:         "node-typescript",
			Adapter:           "osv-stream",
			URL:               "https://api.osv.dev/v1/query",
			SeverityThreshold: "high",
			Enabled:           true,
		},
	},
	"dotnet": {
		{
			ID:        "dotnet-engineering-blog",
			Name:      "Microsoft .NET Engineering & Architecture",
			Ecosystem: "dotnet",
			Adapter:   "rss",
			URL:       "https://devblogs.microsoft.com/dotnet/feed/",
			Enabled:   true,
		},
		{
			ID:                "nuget-security-advisories",
			Name:              "NuGet Security Advisories",
			Ecosystem:         "dotnet",
			Adapter:           "osv-stream",
			URL:               "https://api.osv.dev/v1/query",
			SeverityThreshold: "high",
			Enabled:           true,
		},
	},
	"python": {
		{
			ID:        "python-pep-updates",
			Name:      "Python Enhancement Proposals (PEPs)",
			Ecosystem: "python",
			Adapter:   "rss",
			URL:       "https://peps.python.org/peps.rss",
			Enabled:   true,
		},
		{
			ID:                "pypi-advisories",
			Name:              "PyPI Security Advisories",
			Ecosystem:         "python",
			Adapter:           "osv-stream",
			URL:               "https://api.osv.dev/v1/query",
			SeverityThreshold: "high",
			Enabled:           true,
		},
	},
}

// DefaultConfig provides embedded sensible defaults with radar disabled by default.
func DefaultConfig() *RadarConfig {
	return &RadarConfig{
		Version: "1.0",
		Settings: RadarSettings{
			Enabled:              false, // Disabled by default
			SyncInterval:         "24h",
			MaxFactsPerFeed:      50,
			AutoDetectEcosystems: false, // Disabled by default
			QuarantineUnverified: true,
			MinConfidence:        "high",
			MinSeverity:          SeverityHigh, // Filter out low/info noise by default
			FactTTL:              "90d",
		},
		EnabledPacks: []string{
			"go-rust",
			"security-core",
			"cloud-arch",
		},
		CustomFeeds: []FeedConfig{},
	}
}

// LoadConfig loads radar configuration from designated path, or checks:
// 1. .coppermind/radar.yaml (project local)
// 2. ~/.coppermind/radar.yaml (user global)
// 3. Fallback to DefaultConfig()
func LoadConfig(path string) (*RadarConfig, error) {
	if path == "" {
		if _, err := os.Stat(".coppermind/radar.yaml"); err == nil {
			path = ".coppermind/radar.yaml"
		} else {
			home, err := os.UserHomeDir()
			if err == nil {
				candidate := filepath.Join(home, ".coppermind", "radar.yaml")
				if _, err := os.Stat(candidate); err == nil {
					path = candidate
				}
			}
		}
	}

	if path == "" {
		return DefaultConfig(), nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultConfig(), nil
		}
		return nil, fmt.Errorf("failed to read radar config %q: %w", path, err)
	}

	var cfg RadarConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse radar YAML in %q: %w", path, err)
	}

	if len(cfg.EnabledPacks) == 0 && len(cfg.CustomFeeds) == 0 {
		return DefaultConfig(), nil
	}

	return &cfg, nil
}

// ActiveFeeds aggregates all configured feeds across enabled packs and custom feeds.
// If radar is disabled (Settings.Enabled == false), ActiveFeeds returns nil.
func (c *RadarConfig) ActiveFeeds() []FeedConfig {
	if !c.Settings.Enabled {
		return nil
	}

	var feeds []FeedConfig
	seen := make(map[string]bool)

	for _, pack := range c.EnabledPacks {
		if packFeeds, ok := CuratedPackFeeds[pack]; ok {
			for _, f := range packFeeds {
				if f.Enabled && !seen[f.ID] {
					feeds = append(feeds, f)
					seen[f.ID] = true
				}
			}
		}
	}

	for _, f := range c.CustomFeeds {
		if f.Enabled && !seen[f.ID] {
			feeds = append(feeds, f)
			seen[f.ID] = true
		}
	}

	return feeds
}

// DetectWorkspaceEcosystems inspects rootDir for manifest files to determine active languages.
func DetectWorkspaceEcosystems(rootDir string) []string {
	var ecosystems []string
	seen := make(map[string]bool)

	add := func(eco string) {
		if !seen[eco] {
			ecosystems = append(ecosystems, eco)
			seen[eco] = true
		}
	}

	// Always include security-core and cloud-arch by default
	add("security-core")
	add("cloud-arch")

	_ = filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		// Don't traverse deep into vendor or node_modules or .git
		if info.IsDir() {
			base := info.Name()
			if base == ".git" || base == "node_modules" || base == "vendor" || base == "target" || base == "bin" {
				return filepath.SkipDir
			}
			return nil
		}

		base := info.Name()
		switch {
		case base == "go.mod" || base == "go.sum":
			add("golang")
		case base == "Cargo.toml" || base == "Cargo.lock":
			add("rust")
		case base == "pom.xml" || base == "build.gradle" || base == "build.gradle.kts":
			add("jvm")
		case base == "package.json" || base == "tsconfig.json" || base == "bun.lockb":
			add("node-typescript")
		case strings.HasSuffix(base, ".csproj") || strings.HasSuffix(base, ".sln") || base == "Directory.Build.props":
			add("dotnet")
		case base == "pyproject.toml" || base == "requirements.txt" || base == "Pipfile":
			add("python")
		}

		return nil
	})

	return ecosystems
}
