package project_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bonjoski/coppermind/pkg/brain"
	"github.com/bonjoski/coppermind/pkg/embedding"
	"github.com/bonjoski/coppermind/pkg/project"
	"github.com/bonjoski/coppermind/pkg/scratchpad"
	"github.com/bonjoski/coppermind/pkg/storage/sqlite"
)

func TestProjectManager_LifecycleAndResolution(t *testing.T) {
	tmpDir := t.TempDir()
	pm := project.NewManager(tmpDir)

	// 1. Initial list should bootstrap default projects
	projects, err := pm.ListProjects()
	if err != nil {
		t.Fatalf("ListProjects failed: %v", err)
	}
	if len(projects) < 2 {
		t.Fatalf("expected at least 2 projects (github, personal), got %d", len(projects))
	}

	// 2. Create custom project "work"
	pInfo, err := pm.CreateProject("work")
	if err != nil {
		t.Fatalf("CreateProject failed: %v", err)
	}
	if pInfo.Name != "work" {
		t.Errorf("expected name 'work', got %q", pInfo.Name)
	}
	if pInfo.DataDir != filepath.Join(tmpDir, "projects", "work") {
		t.Errorf("unexpected DataDir: %s", pInfo.DataDir)
	}

	// 3. Resolve explicit project
	name, dir, err := pm.ResolveProject("personal")
	if err != nil {
		t.Fatalf("ResolveProject('personal') failed: %v", err)
	}
	if name != "personal" || dir != filepath.Join(tmpDir, "projects", "personal") {
		t.Errorf("unexpected resolution: name=%s, dir=%s", name, dir)
	}

	// 4. Switch current project
	if err := pm.SetCurrentProject("work"); err != nil {
		t.Fatalf("SetCurrentProject failed: %v", err)
	}

	cfg, err := pm.LoadConfig()
	if err != nil || cfg.CurrentProject != "work" {
		t.Fatalf("expected active project 'work', got %q (err: %v)", cfg.CurrentProject, err)
	}

	// 5. Delete project
	if err := pm.DeleteProject("work"); err != nil {
		t.Fatalf("DeleteProject failed: %v", err)
	}
	// Protected project cannot be deleted
	if err := pm.DeleteProject("github"); err == nil {
		t.Fatalf("expected error deleting protected project 'github'")
	}
}

func TestADV_ProjectNamePathTraversal(t *testing.T) {
	tmpDir := t.TempDir()
	pm := project.NewManager(tmpDir)

	maliciousNames := []string{
		"../escape",
		"../../etc/passwd",
		"/tmp/evil",
		"foo/bar",
		"foo\\bar",
		"project;rm -rf /",
		"test project with spaces",
		"evil\x00null",
	}

	for _, name := range maliciousNames {
		_, err := pm.CreateProject(name)
		if err == nil {
			t.Errorf("expected error creating project with malicious name %q, got nil", name)
		}
		_, _, err = pm.ResolveProject(name)
		if err == nil {
			t.Errorf("expected error resolving project with malicious name %q, got nil", name)
		}
	}

	// CreateProject with empty or whitespace must fail
	if _, err := pm.CreateProject(""); err == nil {
		t.Errorf("expected error creating project with empty name")
	}
	if _, err := pm.CreateProject("   "); err == nil {
		t.Errorf("expected error creating project with whitespace name")
	}
}

func TestADV_ProjectVaultCrossContaminationIsolation(t *testing.T) {
	tmpDir := t.TempDir()
	pm := project.NewManager(tmpDir)

	_, personalDir, err := pm.ResolveProject("personal")
	if err != nil {
		t.Fatalf("failed to resolve personal project: %v", err)
	}
	_, githubDir, err := pm.ResolveProject("github")
	if err != nil {
		t.Fatalf("failed to resolve github project: %v", err)
	}

	// Initialize two independent brain managers bound to distinct project vault DBs
	storePersonal, err := sqlite.NewSQLiteStore(filepath.Join(personalDir, "coppermind.db"))
	if err != nil {
		t.Fatalf("failed to open personal store: %v", err)
	}
	defer storePersonal.Close()

	storeGithub, err := sqlite.NewSQLiteStore(filepath.Join(githubDir, "coppermind.db"))
	if err != nil {
		t.Fatalf("failed to open github store: %v", err)
	}
	defer storeGithub.Close()

	embedder := embedding.NewEmbedderFromEnv()
	brainPersonal := brain.NewManager(storePersonal, embedder, scratchpad.NewMemoryScratchpad())
	brainGithub := brain.NewManager(storeGithub, embedder, scratchpad.NewMemoryScratchpad())

	ctx := context.Background()

	// 1. Store confidential family/dog memories strictly in Personal vault
	_, err = brainPersonal.Remember(ctx, brain.RememberRequest{
		SessionID: "home",
		Category:  "family",
		Content:   "Bailey the golden retriever is allergic to chicken. Vet is Dr. Smith.",
	})
	if err != nil {
		t.Fatalf("failed to store personal memory: %v", err)
	}

	// 2. Store technical infrastructure memories strictly in Github vault
	_, err = brainGithub.Remember(ctx, brain.RememberRequest{
		SessionID: "spanreed",
		Category:  "architecture",
		Content:   "Airlock enforces Tier 1 kernel sandbox with Landlock and macOS Seatbelt.",
	})
	if err != nil {
		t.Fatalf("failed to store github memory: %v", err)
	}

	// 3. Verify total memory counts are strictly isolated (1 memory per vault)
	countPersonal, err := brainPersonal.Count(ctx, "")
	if err != nil || countPersonal != 1 {
		t.Fatalf("expected exactly 1 memory in personal vault, got %d (err: %v)", countPersonal, err)
	}

	countGithub, err := brainGithub.Count(ctx, "")
	if err != nil || countGithub != 1 {
		t.Fatalf("expected exactly 1 memory in github vault, got %d (err: %v)", countGithub, err)
	}

	// 4. Recall in Personal: should find Bailey, and must NEVER contain Airlock
	resultsPersonalDog, err := brainPersonal.Recall(ctx, brain.RecallRequest{
		Query:  "What is Bailey allergic to?",
		Hybrid: true,
	})
	if err != nil || len(resultsPersonalDog) == 0 {
		t.Fatalf("personal recall for dog failed: %v", err)
	}
	if resultsPersonalDog[0].Node.Category != "family" {
		t.Errorf("expected category 'family', got %q", resultsPersonalDog[0].Node.Category)
	}

	resultsPersonalAirlock, err := brainPersonal.Recall(ctx, brain.RecallRequest{
		Query:  "How does Airlock enforce kernel sandbox?",
		Hybrid: true,
	})
	if err != nil {
		t.Fatalf("personal recall search errored: %v", err)
	}
	for _, r := range resultsPersonalAirlock {
		if r.Node.Category == "architecture" || strings.Contains(r.Node.Content, "Airlock") {
			t.Fatalf("CROSS-CONTAMINATION LEAK! Personal vault returned technical github memory: %+v", r.Node.Content)
		}
	}

	// 5. Recall in Github: should find Airlock, and must NEVER contain Bailey
	resultsGithubAirlock, err := brainGithub.Recall(ctx, brain.RecallRequest{
		Query:  "How does Airlock enforce kernel sandbox?",
		Hybrid: true,
	})
	if err != nil || len(resultsGithubAirlock) == 0 {
		t.Fatalf("github recall for airlock failed: %v", err)
	}
	if resultsGithubAirlock[0].Node.Category != "architecture" {
		t.Errorf("expected category 'architecture', got %q", resultsGithubAirlock[0].Node.Category)
	}

	resultsGithubDog, err := brainGithub.Recall(ctx, brain.RecallRequest{
		Query:  "What is Bailey allergic to?",
		Hybrid: true,
	})
	if err != nil {
		t.Fatalf("github recall search errored: %v", err)
	}
	for _, r := range resultsGithubDog {
		if r.Node.Category == "family" || strings.Contains(r.Node.Content, "Bailey") {
			t.Fatalf("CROSS-CONTAMINATION LEAK! Github vault returned personal dog memory: %+v", r.Node.Content)
		}
	}
}

func TestConfig_PersistenceAndPreservation(t *testing.T) {
	tmpDir := t.TempDir()
	pm := project.NewManager(tmpDir)

	initialCfg := project.Config{
		Provider: "gemini",
		Model:    "gemini-3.5-flash-lite",
		Endpoint: "https://generativelanguage.googleapis.com/v1beta/openai",
	}

	if err := pm.SaveConfig(initialCfg); err != nil {
		t.Fatalf("SaveConfig failed: %v", err)
	}

	// Update current project
	if err := pm.SetCurrentProject("github"); err != nil {
		t.Fatalf("SetCurrentProject failed: %v", err)
	}

	loaded, err := pm.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if loaded.CurrentProject != "github" {
		t.Errorf("expected CurrentProject 'github', got %q", loaded.CurrentProject)
	}
	if loaded.Provider != "gemini" {
		t.Errorf("expected Provider 'gemini' preserved, got %q", loaded.Provider)
	}
	if loaded.Model != "gemini-3.5-flash-lite" {
		t.Errorf("expected Model 'gemini-3.5-flash-lite' preserved, got %q", loaded.Model)
	}
	if loaded.Endpoint != "https://generativelanguage.googleapis.com/v1beta/openai" {
		t.Errorf("expected Endpoint preserved, got %q", loaded.Endpoint)
	}
}
