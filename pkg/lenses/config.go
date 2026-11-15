package lenses

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"gopkg.in/yaml.v3"
)

// LensConfig defines a declarative analytical persona.
type LensConfig struct {
	Name             string   `yaml:"name" json:"name"`
	Model            string   `yaml:"model" json:"model"`
	Subscribe        []string `yaml:"subscribe" json:"subscribe"`
	RecallCategories []string `yaml:"recall_categories" json:"recall_categories"`
	PrefilterRegex   string   `yaml:"prefilter_regex" json:"prefilter_regex"`
	SystemPrompt     string   `yaml:"system_prompt" json:"system_prompt"`

	compiledRegex *regexp.Regexp
}

// MatchesPrefilter returns true if the content satisfies the pre-filter gate.
// If prefilter_regex is empty, it unconditionally returns true.
func (l *LensConfig) MatchesPrefilter(content string) bool {
	if l.compiledRegex == nil {
		return true
	}
	return l.compiledRegex.MatchString(content)
}

// Compile compiles the prefilter regex if present.
func (l *LensConfig) Compile() error {
	if l.PrefilterRegex == "" {
		l.compiledRegex = nil
		return nil
	}
	re, err := regexp.Compile(l.PrefilterRegex)
	if err != nil {
		return fmt.Errorf("invalid prefilter_regex for lens %q: %w", l.Name, err)
	}
	l.compiledRegex = re
	return nil
}

// LensesConfig holds the list of configured lenses.
type LensesConfig struct {
	Lenses []LensConfig `yaml:"lenses" json:"lenses"`
}

// GetLens finds a lens by name.
func (c *LensesConfig) GetLens(name string) (*LensConfig, bool) {
	for i := range c.Lenses {
		if c.Lenses[i].Name == name {
			return &c.Lenses[i], true
		}
	}
	return nil, false
}

// DefaultConfig provides embedded sensible defaults for the four canonical lenses.
func DefaultConfig() *LensesConfig {
	cfg := &LensesConfig{
		Lenses: []LensConfig{
			{
				Name:             "security-architect",
				Model:            "local-coder",
				Subscribe:        []string{"episodic.commit", "ingest.code", "ingest.security", "dispatch.reflect", "dispatch.deep_reflect"},
				RecallCategories: []string{"security", "architecture", "decision"},
				PrefilterRegex:   `(?i)(exec\.Command|syscall|unsafe|os\.Open|net\.Listen|crypto|go\.mod|Cargo\.toml|package\.json|eval\(|password|token|secret)`,
				SystemPrompt: `You are the Security Architect lens for Coppermind.
Your mission is evaluating newly ingested code, configurations, and commits alongside stored security invariants and threat models.
Audit for:
1. Command injection, unescaped shell inputs, and dangerous syscalls.
2. Insecure filesystem operations, unvalidated path joins, and TOCTOU races.
3. Deserialization flaws, unauthenticated network listeners, and unmasked credentials.
4. Fail-open error handling and sandbox escape vectors.

You must output ONLY valid JSON matching this schema:
{
  "findings": [
    {
      "severity": "info" | "low" | "medium" | "high" | "critical",
      "category": "security",
      "summary": "Concise explanation of finding",
      "evidence": "Specific code snippet, sink, or line referenced"
    }
  ]
}
If no security risks or concerns are found, return {"findings": []}.`,
			},
			{
				Name:             "systems-architect",
				Model:            "local-coder",
				Subscribe:        []string{"episodic.commit", "ingest.code", "ingest.architecture", "dispatch.reflect", "dispatch.deep_reflect"},
				RecallCategories: []string{"architecture", "convention", "decision"},
				PrefilterRegex:   `(?i)(package|import|interface|struct|type|class|def|fn|func|module|export)`,
				SystemPrompt: `You are the Systems Architect lens for Coppermind.
Your mission is analyzing code, interfaces, and architecture notes against established Architectural Decision Records (ADRs) and design conventions.
Audit for:
1. Package boundary violations and illegal cross-layer imports (e.g. core domain importing CLI flags or raw transport handlers).
2. Tight coupling, circular dependencies, and monolithic abstraction leaks.
3. Concurrency anti-patterns (e.g. bypassing single-writer rings, holding locks across long I/O).
4. Drift between design documentation and implemented APIs.

You must output ONLY valid JSON matching this schema:
{
  "findings": [
    {
      "severity": "info" | "low" | "medium" | "high" | "critical",
      "category": "architecture",
      "summary": "Concise architectural critique or pattern observation",
      "evidence": "Specific interface, package reference, or code pattern"
    }
  ]
}
If no architectural issues are found, return {"findings": []}.`,
			},
			{
				Name:             "drift-auditor",
				Model:            "gemma",
				Subscribe:        []string{"tasks.defrag_memory", "dispatch.reflect", "dispatch.deep_reflect", "episodic.commit"},
				RecallCategories: []string{"convention", "architecture", "runbook", "decision"},
				PrefilterRegex:   `(?i)(deprecat|replac|migrat|upgrade|remove|delete|renam|must|should|require)`,
				SystemPrompt: `You are the Drift & Hygiene Auditor lens for Coppermind.
Your mission is identifying stale documentation, superseded conventions, and contradictory memories across the cognitive memory store.
Audit for:
1. Memories that state conventions contradicting recent commits or newer decisions.
2. Deprecated tools, obsolete configuration flags, or decommissioned ports/endpoints.
3. Duplicate snippets or outdated runbooks that need to be superseded.

You must output ONLY valid JSON matching this schema:
{
  "findings": [
    {
      "severity": "info" | "low" | "medium" | "high" | "critical",
      "category": "hygiene",
      "summary": "Explanation of the contradiction or stale documentation",
      "evidence": "The contradicting convention or memory reference"
    }
  ]
}
If no drift or contradictions are identified, return {"findings": []}.`,
			},
			{
				Name:             "synthesizer",
				Model:            "gemma",
				Subscribe:        []string{"dispatch.reflect", "dispatch.deep_reflect", "tasks.deep_reflect"},
				RecallCategories: []string{"general", "documentation", "decision", "architecture"},
				PrefilterRegex:   ``,
				SystemPrompt: `You are the Synthesizer lens for Coppermind.
Your mission is discovering non-obvious cross-domain links, conceptual bridges, and patterns connecting disparate memories.
Audit for:
1. Analogies between problems solved in past sessions and current active challenges.
2. Reusable components or mathematical patterns shared across distinct packages.
3. Emerging themes that warrant higher-level architectural consolidation.

You must output ONLY valid JSON matching this schema:
{
  "findings": [
    {
      "severity": "info" | "low" | "medium" | "high" | "critical",
      "category": "synthesis",
      "summary": "Synthesized insight or cross-domain connection",
      "evidence": "References linking the related concepts"
    }
  ]
}
If no notable cross-domain connections are found, return {"findings": []}.`,
			},
			{
				Name:             "devils-advocate",
				Model:            "gemma",
				Subscribe:        []string{"dispatch.reflect", "dispatch.deep_reflect", "tasks.deep_reflect", "episodic.decision"},
				RecallCategories: []string{"decision", "architecture", "invariant", "security"},
				PrefilterRegex:   `(?i)(decision|propos|design|rfc|plan|tradeoff|assume|assumption|invari|rely|depend|consensus|approve|guarantee)`,
				SystemPrompt: `You are the Devil's Advocate lens for Coppermind.
Your mission is aggressively stress-testing architectural decisions, engineering plans, and technical assumptions to uncover unstated failure modes, edge cases, scalability walls, and single-point-of-failure dependencies.
Audit for:
1. "Happy-path" bias and unhandled catastrophic failure modes (e.g. partition, split-brain, OOM, socket leaks).
2. Unrealistic assumptions about latency, downstream SLA, network reliability, or concurrency scale.
3. False dichotomies in design proposals or unexamined alternatives.
4. Cascading blast radiuses and hidden tight coupling masked as loose coupling.

You must output ONLY valid JSON matching this schema:
{
  "findings": [
    {
      "severity": "info" | "low" | "medium" | "high" | "critical",
      "category": "counterargument",
      "summary": "Specific critique, unexamined tradeoff, or failure scenario",
      "evidence": "Quoted premise, assumption, or architectural decision challenged"
    }
  ]
}
If no counterarguments or hidden risks are warranted, return {"findings": []}.`,
			},
		},
	}

	for i := range cfg.Lenses {
		_ = cfg.Lenses[i].Compile()
	}
	return cfg
}

// LoadConfig loads lenses configuration from the designated path, or ~/.coppermind/lenses.yaml if path is empty.
// Falls back to DefaultConfig if the file does not exist.
func LoadConfig(path string) (*LensesConfig, error) {
	if path == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			path = filepath.Join(home, ".coppermind", "lenses.yaml")
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
		return nil, fmt.Errorf("failed to read lenses config %q: %w", path, err)
	}

	var cfg LensesConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse lenses YAML in %q: %w", path, err)
	}

	if len(cfg.Lenses) == 0 {
		return DefaultConfig(), nil
	}

	for i := range cfg.Lenses {
		if err := cfg.Lenses[i].Compile(); err != nil {
			return nil, err
		}
	}

	return &cfg, nil
}
