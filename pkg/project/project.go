package project

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/bonjoski/coppermind/pkg/gitscope"
)

var validProjectNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_\-\.]{1,64}$`)

// Config models the top-level Coppermind user configuration.
type Config struct {
	CurrentProject string `json:"current_project,omitempty"`
	Provider       string `json:"provider,omitempty"`
	Model          string `json:"model,omitempty"`
	Endpoint       string `json:"endpoint,omitempty"`
	APIKey         string `json:"api_key,omitempty"`
}

// ProjectInfo provides metadata regarding an isolated cognitive vault.
type ProjectInfo struct {
	Name        string    `json:"name"`
	DataDir     string    `json:"data_dir"`
	DBPath      string    `json:"db_path"`
	IsActive    bool      `json:"is_active"`
	MemoryCount int       `json:"memory_count"`
	CreatedAt   time.Time `json:"created_at"`
}

// Manager coordinates project vault isolation, switching, and discovery.
type Manager struct {
	rootDataDir string
}

// NewManager creates a project manager operating within rootDataDir (defaults to ~/.coppermind).
func NewManager(rootDataDir string) *Manager {
	if rootDataDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			rootDataDir = ".coppermind"
		} else {
			rootDataDir = filepath.Join(home, ".coppermind")
		}
	}
	_ = os.MkdirAll(rootDataDir, 0700)
	_ = os.MkdirAll(filepath.Join(rootDataDir, "projects"), 0700)
	return &Manager{rootDataDir: rootDataDir}
}

// ResolveProject identifies the target project based on precedence:
// 1. Explicit override flag
// 2. COPPERMIND_PROJECT environment variable
// 3. Ambient Git context (if inside a git repository, defaults to "github")
// 4. Configured active project in config.json
// 5. Default project ("github")
func (m *Manager) ResolveProject(explicit string) (string, string, error) {
	projectName := strings.TrimSpace(explicit)

	if projectName == "" {
		projectName = strings.TrimSpace(os.Getenv("COPPERMIND_PROJECT"))
	}

	if projectName == "" {
		// Ambient Git context check
		gitCtx := gitscope.Detect("")
		if gitCtx.IsGit {
			projectName = "github"
		}
	}

	if projectName == "" {
		cfg, err := m.LoadConfig()
		if err == nil && cfg.CurrentProject != "" {
			projectName = cfg.CurrentProject
		}
	}

	if projectName == "" {
		projectName = "github"
	}

	if !validProjectNameRegex.MatchString(projectName) {
		return "", "", fmt.Errorf("invalid project name %q: must match %s", projectName, validProjectNameRegex.String())
	}

	projectDir := filepath.Join(m.rootDataDir, "projects", projectName)
	_ = os.MkdirAll(projectDir, 0700)

	// Migration: If root coppermind.db exists and this is the "github" or "default" project,
	// and projects/github/coppermind.db does not exist yet, migrate root database into the vault!
	m.migrateRootDBIfNeeded(projectName, projectDir)

	return projectName, projectDir, nil
}

func (m *Manager) migrateRootDBIfNeeded(projectName, projectDir string) {
	if projectName != "github" && projectName != "default" {
		return
	}
	destDB := filepath.Join(projectDir, "coppermind.db")
	if _, err := os.Stat(destDB); err == nil {
		return // Vault already has its DB
	}

	rootDB := filepath.Join(m.rootDataDir, "coppermind.db")
	if info, err := os.Stat(rootDB); err == nil && !info.IsDir() {
		// Copy or move root database into project vault
		data, err := os.ReadFile(rootDB)
		if err == nil {
			_ = os.WriteFile(destDB, data, 0600)
		}
	}
}

// ListProjects returns all available isolated vaults.
func (m *Manager) ListProjects() ([]ProjectInfo, error) {
	projectsDir := filepath.Join(m.rootDataDir, "projects")
	entries, err := os.ReadDir(projectsDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read projects directory: %w", err)
	}

	cfg, _ := m.LoadConfig()
	active := cfg.CurrentProject
	if active == "" {
		active = "github"
	}

	var list []ProjectInfo
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		dataDir := filepath.Join(projectsDir, name)
		dbPath := filepath.Join(dataDir, "coppermind.db")
		info, _ := e.Info()

		createdAt := time.Now()
		if info != nil {
			createdAt = info.ModTime()
		}

		list = append(list, ProjectInfo{
			Name:      name,
			DataDir:   dataDir,
			DBPath:    dbPath,
			IsActive:  name == active,
			CreatedAt: createdAt,
		})
	}

	// Always ensure at least "github" and "personal" exist
	if len(list) == 0 {
		_, _ = m.CreateProject("github")
		_, _ = m.CreateProject("personal")
		return m.ListProjects()
	}

	return list, nil
}

// CreateProject provisions a new isolated project vault.
func (m *Manager) CreateProject(name string) (ProjectInfo, error) {
	name = strings.TrimSpace(name)
	if !validProjectNameRegex.MatchString(name) {
		return ProjectInfo{}, fmt.Errorf("invalid project name %q", name)
	}

	projectDir := filepath.Join(m.rootDataDir, "projects", name)
	if err := os.MkdirAll(projectDir, 0700); err != nil {
		return ProjectInfo{}, fmt.Errorf("failed to create project directory: %w", err)
	}

	return ProjectInfo{
		Name:      name,
		DataDir:   projectDir,
		DBPath:    filepath.Join(projectDir, "coppermind.db"),
		CreatedAt: time.Now(),
	}, nil
}

// SetCurrentProject sets the active project in config.json.
func (m *Manager) SetCurrentProject(name string) error {
	name = strings.TrimSpace(name)
	if !validProjectNameRegex.MatchString(name) {
		return fmt.Errorf("invalid project name %q", name)
	}

	// Ensure vault directory exists
	_, _ = m.CreateProject(name)

	cfg, _ := m.LoadConfig()
	cfg.CurrentProject = name
	return m.SaveConfig(cfg)
}

// SaveConfig writes config.json preserving file mode 0600.
func (m *Manager) SaveConfig(cfg Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(m.rootDataDir, "config.json"), data, 0600)
}

// LoadConfig reads config.json.
func (m *Manager) LoadConfig() (Config, error) {
	var cfg Config
	cfgPath := filepath.Join(m.rootDataDir, "config.json")
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, err
	}
	err = json.Unmarshal(data, &cfg)
	return cfg, err
}

// DeleteProject deletes an isolated project vault.
func (m *Manager) DeleteProject(name string) error {
	name = strings.TrimSpace(name)
	if name == "" || name == "github" {
		return fmt.Errorf("cannot delete protected default project %q", name)
	}

	projectDir := filepath.Join(m.rootDataDir, "projects", name)
	return os.RemoveAll(projectDir)
}
