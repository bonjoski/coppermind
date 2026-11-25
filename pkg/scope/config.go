package scope

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	// ConfigFileName is the repo-confined declarative scope manifest filename.
	ConfigFileName = ".coppermind.yaml"
	// MaxConfigBytes hard-caps .coppermind.yaml size to prevent memory/YAML DoS.
	MaxConfigBytes = 16 * 1024
	// MaxWalkDepth bounds upward directory traversal inside a git repository root.
	MaxWalkDepth = 16
)

var (
	// ErrConfigSymlinkRefused rejects symlinked .coppermind.yaml files fail-closed.
	ErrConfigSymlinkRefused = errors.New("scope config security violation: symlinked .coppermind.yaml refused fail-closed")
	// ErrConfigTooLarge rejects oversized .coppermind.yaml files fail-closed.
	ErrConfigTooLarge = errors.New("scope config security violation: .coppermind.yaml exceeds 16 KiB limit")
)

// WorkspaceConfig models the strictly allowlisted fields of .coppermind.yaml.
// Unknown fields (e.g. project, hooks, db_path) fail closed via KnownFields(true).
type WorkspaceConfig struct {
	Scope string            `yaml:"scope"`
	Paths map[string]string `yaml:"paths"`
}

// LoadConfigFile reads and strictly validates relPath inside an os.OpenRoot boundary.
func LoadConfigFile(rootFS *os.Root, relPath string) (*WorkspaceConfig, error) {
	if rootFS == nil {
		return nil, fmt.Errorf("confined rootFS is required")
	}
	fi, err := rootFS.Lstat(relPath)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: %s", ErrConfigSymlinkRefused, relPath)
	}
	if fi.IsDir() {
		return nil, fmt.Errorf("scope config %q is a directory", relPath)
	}

	f, err := rootFS.Open(relPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, MaxConfigBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxConfigBytes {
		return nil, fmt.Errorf("%w: %s", ErrConfigTooLarge, relPath)
	}

	var cfg WorkspaceConfig
	if len(bytes.TrimSpace(data)) > 0 {
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("invalid %s: %w", ConfigFileName, err)
		}
	}

	normScope, err := Normalize(cfg.Scope)
	if err != nil {
		return nil, fmt.Errorf("invalid scope in %s: %w", ConfigFileName, err)
	}
	cfg.Scope = normScope

	if len(cfg.Paths) > 0 {
		cleanPaths := make(map[string]string, len(cfg.Paths))
		for rawRel, rawSc := range cfg.Paths {
			relKey, pErr := normalizeConfigRelPath(rawRel)
			if pErr != nil {
				return nil, fmt.Errorf("invalid path key %q in %s: %w", rawRel, ConfigFileName, pErr)
			}
			scVal, sErr := Normalize(rawSc)
			if sErr != nil {
				return nil, fmt.Errorf("invalid path scope %q for %q in %s: %w", rawSc, rawRel, ConfigFileName, sErr)
			}
			if scVal == "" {
				return nil, fmt.Errorf("empty scope for path %q in %s", rawRel, ConfigFileName)
			}
			cleanPaths[relKey] = scVal
		}
		cfg.Paths = cleanPaths
	}

	return &cfg, nil
}

func normalizeConfigRelPath(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" || strings.Contains(s, "\\") || strings.HasPrefix(s, "/") {
		return "", fmt.Errorf("path must be a non-empty relative slash path")
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] >= 0x7f {
			return "", fmt.Errorf("path contains control or non-ASCII bytes")
		}
	}
	clean := path.Clean(s)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") {
		return "", fmt.Errorf("path traversal rejected")
	}
	return clean, nil
}

// MatchPath resolves the longest matching prefix from cfg.Paths for relFromConfig,
// falling back to cfg.Scope when no path rule matches.
func (c *WorkspaceConfig) MatchPath(relFromConfig string) string {
	if c == nil {
		return ""
	}
	rel := path.Clean(strings.ReplaceAll(strings.TrimSpace(relFromConfig), "\\", "/"))
	if rel == "." || rel == "" || len(c.Paths) == 0 {
		return c.Scope
	}
	bestLen := -1
	bestScope := ""
	for prefix, sc := range c.Paths {
		if rel == prefix || strings.HasPrefix(rel, prefix+"/") {
			if len(prefix) > bestLen {
				bestLen = len(prefix)
				bestScope = sc
			}
		}
	}
	if bestScope != "" {
		return bestScope
	}
	return c.Scope
}

// ResolveFromDir walks upward from cwd up to repoRoot (strictly confined via os.OpenRoot)
// looking for the nearest .coppermind.yaml manifest. If repoRoot is empty, only cwd itself
// is inspected (never traverses upward into untrusted parent directories).
func ResolveFromDir(cwd, repoRoot string) (string, error) {
	if strings.TrimSpace(cwd) == "" {
		var err error
		cwd, err = os.Getwd()
		if err != nil {
			return "", nil
		}
	}
	absCwd, err := filepath.Abs(cwd)
	if err != nil {
		return "", nil
	}
	if resolved, rErr := filepath.EvalSymlinks(absCwd); rErr == nil {
		absCwd = resolved
	}

	absRoot := strings.TrimSpace(repoRoot)
	if absRoot == "" {
		absRoot = absCwd
	} else {
		if a, aErr := filepath.Abs(absRoot); aErr == nil {
			absRoot = a
		}
		if resolved, rErr := filepath.EvalSymlinks(absRoot); rErr == nil {
			absRoot = resolved
		}
	}

	relCwd, err := filepath.Rel(absRoot, absCwd)
	if err != nil || relCwd == ".." || strings.HasPrefix(relCwd, ".."+string(filepath.Separator)) {
		// cwd is outside repoRoot: confine inspection strictly to absCwd itself.
		absRoot = absCwd
		relCwd = "."
	}

	rootFS, err := os.OpenRoot(absRoot)
	if err != nil {
		return "", nil
	}
	defer rootFS.Close()

	relSlash := filepath.ToSlash(relCwd)
	if relSlash == "" {
		relSlash = "."
	}
	cur := relSlash
	for depth := 0; depth <= MaxWalkDepth; depth++ {
		cfgRel := ConfigFileName
		if cur != "." {
			cfgRel = path.Join(cur, ConfigFileName)
		}
		_, statErr := rootFS.Lstat(cfgRel)
		if statErr == nil {
			cfg, loadErr := LoadConfigFile(rootFS, cfgRel)
			if loadErr != nil {
				return "", loadErr
			}
			relFromCfg := relSlash
			if cur != "." {
				if relSlash == cur {
					relFromCfg = "."
				} else {
					relFromCfg = strings.TrimPrefix(relSlash, cur+"/")
				}
			}
			return cfg.MatchPath(relFromCfg), nil
		}
		if !os.IsNotExist(statErr) {
			return "", statErr
		}
		if cur == "." {
			break
		}
		parent := path.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}

	return "", nil
}

// Resolve applies the canonical 4-tier scope resolution precedence:
//  1. Explicit flag / MCP argument
//  2. COPPERMIND_SCOPE environment variable
//  3. Repo-confined .coppermind.yaml from cwd up to repoRoot
//  4. Empty string "" (vault-global)
func Resolve(explicit, cwd, repoRoot string) (string, error) {
	if explicit != "" {
		return Normalize(explicit)
	}
	if env := os.Getenv("COPPERMIND_SCOPE"); env != "" {
		return Normalize(env)
	}
	return ResolveFromDir(cwd, repoRoot)
}

// ResolveFileScope resolves the scope for a file at relFilePath inside absRoot using
// .coppermind.yaml when useConfig is true, falling back to normalized baseScope.
func ResolveFileScope(absRoot, relFilePath, baseScope string, useConfig bool) (string, error) {
	base, err := Normalize(baseScope)
	if err != nil {
		return "", err
	}
	if !useConfig {
		return base, nil
	}
	fileDir := filepath.Dir(filepath.Join(absRoot, filepath.FromSlash(relFilePath)))
	sc, err := ResolveFromDir(fileDir, absRoot)
	if err != nil {
		return "", err
	}
	if sc != "" {
		return sc, nil
	}
	return base, nil
}
