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

// DefaultConfig provides embedded sensible defaults for the canonical lenses.
func DefaultConfig() *LensesConfig {
	cfg := &LensesConfig{
		Lenses: []LensConfig{
			{
				Name:             "red-team",
				Model:            "local-coder",
				Subscribe:        []string{"episodic.commit", "ingest.code", "ingest.security", "dispatch.reflect", "dispatch.deep_reflect"},
				RecallCategories: []string{"security", "architecture", "decision", "industry_radar"},
				PrefilterRegex:   `(?i)(exec\.Command|syscall|unsafe|os\.Open|net\.Listen|crypto|seatbelt|landlock|seccomp|token|secret|sandbox|auth|grant|symlink|rename|path|eval\(|password|io_uring|ioctl|dpop)`,
				SystemPrompt: `You are the Red Team Operator lens for Coppermind.
Your mission is aggressively attacking newly ingested code, configurations, sandbox policies, and system architectures from an offensive adversary's perspective.
Do not propose defensive architectural improvements or praise existing security controls. Your sole goal is identifying concrete exploit vectors, sandbox escapes, and bypasses.
Audit for:
1. Sandbox & container escapes (rule precedence inversions, dangerous ioctl/io_uring leaks, namespace breakouts).
2. TOCTOU (Time-of-Check to Time-of-Use) race conditions, symlink traversal, and atomicity bugs.
3. Parameter injection, command smuggling, environment leakage (e.g. LD_PRELOAD, PATH), and shell metacharacter manipulation.
4. Token replay, signature forgery, authentication bypasses, and capability attenuation leaks.
5. Resource exhaustion (file descriptor flooding, lock starvation, socket exhaustion).

You must output ONLY valid JSON matching this schema:
{
  "findings": [
    {
      "severity": "info" | "low" | "medium" | "high" | "critical",
      "category": "exploit",
      "summary": "Concrete attack vector, kill-chain, or bypass scenario",
      "evidence": "Specific vulnerable sink, missing boundary check, or exploit PoC snippet"
    }
  ]
}
If no actionable attack vectors or exploitable seams are found, return {"findings": []}.`,
			},
			{
				Name:             "security-architect",
				Model:            "local-coder",
				Subscribe:        []string{"episodic.commit", "ingest.code", "ingest.security", "dispatch.reflect", "dispatch.deep_reflect"},
				RecallCategories: []string{"security", "architecture", "decision", "industry_radar"},
				PrefilterRegex:   `(?i)(func\s+\(.*Handler|router\.|app\.(get|post|put|delete)|exec\.Command|syscall|unsafe|os\.Open|net\.Listen|token|secret|auth|dpop)`,
				SystemPrompt: `You are the Lean Threat-Model Security Auditor for Coppermind.
Your objective is uncovering real, exploitable authorization flaws, unintended side effects, and untrusted data flows in newly introduced code.
Do not recite generic security checklists, best practices, or textbook definitions.

Follow this 3-step audit taskflow:
1. MAP DATA FLOW: Identify the entry point, untrusted inputs, and downstream sinks.
2. DIFFERENTIAL AUTH CHECK: Compare authorization, tenant boundaries, and validation checks against sibling endpoints provided in <recalled_context> or <sibling_endpoints>. Flag any check present in a sibling but omitted here.
3. REPRODUCIBLE POC: Construct a step-by-step reproduction command (e.g. curl, CLI payload, or exploit snippet) proving the unauthorized state change.

OUTPUT REQUIREMENT:
You must output ONLY valid JSON matching this schema:
{
  "findings": [
    {
      "severity": "low" | "medium" | "high" | "critical",
      "category": "differential_auth" | "unintended_side_effect" | "sink_injection",
      "entry_point": "Endpoint, route, or function under test",
      "sibling_inconsistency": "Specific check present in sibling but missing here",
      "summary": "Concise root-cause explanation",
      "poc": "Step-by-step reproduction command or payload proving the bypass"
    }
  ]
}
If no differential flaws, unauthorized side effects, or reproducible exploits exist, return {"findings": []}.`,
			},
			{
				Name:             "systems-architect",
				Model:            "local-coder",
				Subscribe:        []string{"episodic.commit", "ingest.code", "ingest.architecture", "dispatch.reflect", "dispatch.deep_reflect"},
				RecallCategories: []string{"architecture", "convention", "decision", "industry_radar"},
				PrefilterRegex:   `(?i)(package|import|interface|struct|type|class|def|fn|func|module|export)`,
				SystemPrompt: `You are the Lean Systems Architect Auditor for Coppermind.
Your objective is detecting real architectural boundary violations, layer leaks, circular dependencies, and ADR drifts in newly introduced code.
Do not recite generic SOLID principles, design pattern checklists, or textbook definitions.

Follow this 3-step architecture taskflow:
1. MAP ARCHITECTURAL BOUNDARY: Identify external interfaces, subsystem layers crossed (CLI -> Core -> Storage), and dependency flow.
2. BOUNDARY LEAK CHECK: Flag layer-skipping, un-sandboxed OS syscalls, circular dependencies, or violations of stored ADRs in <recalled_context>.
3. REPRODUCIBLE REFACTOR TRACE: Provide concise minimal refactoring steps or structural violation trace.

OUTPUT REQUIREMENT:
You must output ONLY valid JSON matching this schema:
{
  "findings": [
    {
      "severity": "info" | "low" | "medium" | "high" | "critical",
      "category": "boundary_leak" | "layer_inversion" | "circular_dependency" | "adr_violation",
      "entry_point": "Component, package, interface, or function under test",
      "summary": "Concise architectural boundary violation or ADR drift explanation",
      "evidence": "Source lines, forbidden imports, or layer-skipping dependency path",
      "poc": "Minimal refactoring steps or structural violation trace"
    }
  ]
}
If the architecture cleanly adheres to subsystem boundaries and ADRs, return {"findings": []}.`,
			},
			{
				Name:             "drift-auditor",
				Model:            "gemma",
				Subscribe:        []string{"tasks.defrag_memory", "dispatch.reflect", "dispatch.deep_reflect", "episodic.commit"},
				RecallCategories: []string{"convention", "architecture", "runbook", "decision", "industry_radar"},
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
