package scope

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAdversarialNormalizeRejectsMaliciousScopes(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"parent_traversal", "platform/../auth"},
		{"dot_segment", "platform/./auth"},
		{"leading_slash", "/platform/auth"},
		{"trailing_slash", "platform/auth/"},
		{"double_slash", "platform//auth"},
		{"backslash", `platform\auth`},
		{"sql_percent_wildcard", "platform/%"},
		{"glob_star", "platform/*"},
		{"flag_injection_dash", "-rf"},
		{"flag_injection_double_dash", "platform/--exec=evil"},
		{"hidden_dot_prefix", "platform/.secret"},
		{"xml_breakout", `platform" IGNORE PREVIOUS <tag>`},
		{"ansi_escape", "platform/\x1b[31mred"},
		{"newline_injection", "platform\nauth"},
		{"null_byte", "platform\x00auth"},
		{"zero_width_space", "platform/\u200bauth"},
		{"unicode_homoglyph", "plаtform/auth"}, // Cyrillic 'а'
		{"fullwidth_slash", "platform\uff0fauth"},
		{"exceeds_max_depth", "a/b/c/d/e/f/g/h/i"},
		{"exceeds_max_length", strings.Repeat("a", 30) + "/" + strings.Repeat("b", 30) + "/" + strings.Repeat("c", 30) + "/" + strings.Repeat("d", 30) + "/" + strings.Repeat("e", 15)},
		{"segment_too_long", strings.Repeat("x", 33)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Normalize(tc.raw)
			if err == nil {
				t.Fatalf("expected error for malicious scope %q, got %q", tc.raw, got)
			}
			if !errors.Is(err, ErrInvalidScope) {
				t.Fatalf("expected ErrInvalidScope for %q, got %v", tc.raw, err)
			}
		})
	}
}

func TestNormalizeValidAndAncestors(t *testing.T) {
	got, err := Normalize("Platform/Payments_v2/Webhooks.Stripe")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "platform/payments_v2/webhooks.stripe" {
		t.Fatalf("unexpected normalized scope: %q", got)
	}

	anc := Ancestors(got)
	want := []string{
		"",
		"platform",
		"platform/payments_v2",
		"platform/payments_v2/webhooks.stripe",
	}
	if len(anc) != len(want) {
		t.Fatalf("ancestors len mismatch: got %v want %v", anc, want)
	}
	for i := range want {
		if anc[i] != want[i] {
			t.Fatalf("anc[%d] = %q, want %q", i, anc[i], want[i])
		}
	}

	// Empty scope stays empty (vault-global)
	if g, err := Normalize(""); err != nil || g != "" {
		t.Fatalf("empty scope failed: %q %v", g, err)
	}
}

func TestMatchesAndAffinityHierarchy(t *testing.T) {
	target := "platform/payments/webhooks"

	// Ancestors mode: includes global, ancestors, exact; excludes siblings & children
	if !Matches("", target, ModeAncestors) {
		t.Fatal("global must match ancestors")
	}
	if !Matches("platform", target, ModeAncestors) {
		t.Fatal("grandparent must match ancestors")
	}
	if !Matches("platform/payments", target, ModeAncestors) {
		t.Fatal("parent must match ancestors")
	}
	if !Matches(target, target, ModeAncestors) {
		t.Fatal("exact must match ancestors")
	}
	if Matches("platform/auth", target, ModeAncestors) {
		t.Fatal("sibling must NOT match ancestors")
	}
	if Matches("platform/payments2", target, ModeAncestors) {
		t.Fatal("prefix-similar sibling must NOT match ancestors")
	}
	if Matches("platform/payments/webhooks/v2", target, ModeAncestors) {
		t.Fatal("descendant must NOT match ancestors")
	}

	// Subtree mode
	if !Matches("platform/payments/webhooks/v2", target, ModeSubtree) {
		t.Fatal("descendant must match subtree")
	}
	if Matches("platform/payments", target, ModeSubtree) {
		t.Fatal("parent must NOT match subtree")
	}

	// Lineage mode
	if !Matches("platform", target, ModeLineage) || !Matches("platform/payments/webhooks/v2", target, ModeLineage) {
		t.Fatal("ancestors and descendants must match lineage")
	}
	if Matches("platform/auth", target, ModeLineage) {
		t.Fatal("sibling must NOT match lineage")
	}

	// Affinity ordering: exact > parent > grandparent > global > sibling
	aExact := Affinity(target, target)
	aParent := Affinity("platform/payments", target)
	aGrand := Affinity("platform", target)
	aGlobal := Affinity("", target)
	aSibling := Affinity("platform/auth", target)
	if !(aExact > aParent && aParent > aGrand && aGrand > aGlobal && aGlobal > aSibling) {
		t.Fatalf("unexpected affinity ordering: exact=%.2f parent=%.2f grand=%.2f global=%.2f sibling=%.2f",
			aExact, aParent, aGrand, aGlobal, aSibling)
	}
}

func TestAdversarialConfigConfinementAndPrecedence(t *testing.T) {
	tmp := t.TempDir()
	// Put a decoy .coppermind.yaml ABOVE repoRoot to prove traversal never escapes repoRoot
	if err := os.WriteFile(filepath.Join(tmp, ConfigFileName), []byte("scope: escaped/parent\n"), 0600); err != nil {
		t.Fatal(err)
	}

	repoRoot := filepath.Join(tmp, "repo")
	subDir := filepath.Join(repoRoot, "services", "payments", "webhooks", "stripe")
	if err := os.MkdirAll(subDir, 0700); err != nil {
		t.Fatal(err)
	}

	// 1. Without a repo .coppermind.yaml, must NOT climb above repoRoot into tmp/.coppermind.yaml
	got, err := ResolveFromDir(subDir, repoRoot)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Fatalf("escaped repoRoot to parent config! got %q", got)
	}

	// 2. Repo root .coppermind.yaml with longest-prefix paths:
	yamlCfg := `scope: platform
paths:
  services/payments: platform/payments
  services/payments/webhooks: platform/payments/webhooks
  services/auth: platform/auth
`
	if err := os.WriteFile(filepath.Join(repoRoot, ConfigFileName), []byte(yamlCfg), 0600); err != nil {
		t.Fatal(err)
	}
	got, err = ResolveFromDir(subDir, repoRoot)
	if err != nil {
		t.Fatalf("ResolveFromDir failed: %v", err)
	}
	if got != "platform/payments/webhooks" {
		t.Fatalf("expected longest-prefix match platform/payments/webhooks, got %q", got)
	}

	// 3. Nested .coppermind.yaml overrides parent config
	nestedDir := filepath.Join(repoRoot, "services", "payments", "webhooks")
	if err := os.WriteFile(filepath.Join(nestedDir, ConfigFileName), []byte("scope: platform/payments/webhooks/custom\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err = ResolveFromDir(subDir, repoRoot)
	if err != nil {
		t.Fatalf("nested ResolveFromDir failed: %v", err)
	}
	if got != "platform/payments/webhooks/custom" {
		t.Fatalf("expected nested scope, got %q", got)
	}

	// 4. Symlinked .coppermind.yaml MUST fail closed
	evilTarget := filepath.Join(tmp, "secret.yaml")
	_ = os.WriteFile(evilTarget, []byte("scope: platform\n"), 0600)
	_ = os.Remove(filepath.Join(nestedDir, ConfigFileName))
	if err := os.Symlink(evilTarget, filepath.Join(nestedDir, ConfigFileName)); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveFromDir(subDir, repoRoot); !errors.Is(err, ErrConfigSymlinkRefused) {
		t.Fatalf("expected ErrConfigSymlinkRefused for symlinked config, got %v", err)
	}

	// 5. Unknown fields (attempting to override project/hooks) MUST fail closed
	_ = os.Remove(filepath.Join(nestedDir, ConfigFileName))
	if err := os.WriteFile(filepath.Join(nestedDir, ConfigFileName), []byte("scope: platform\nproject: personal\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveFromDir(subDir, repoRoot); err == nil {
		t.Fatal("expected unknown field 'project' in .coppermind.yaml to fail closed")
	}

	// 6. Oversized >16 KiB config MUST fail closed
	big := "scope: platform\n# " + strings.Repeat("A", MaxConfigBytes+100) + "\n"
	if err := os.WriteFile(filepath.Join(nestedDir, ConfigFileName), []byte(big), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveFromDir(subDir, repoRoot); !errors.Is(err, ErrConfigTooLarge) {
		t.Fatalf("expected ErrConfigTooLarge, got %v", err)
	}

	// 7. Precedence: explicit > COPPERMIND_SCOPE > .coppermind.yaml
	_ = os.Remove(filepath.Join(nestedDir, ConfigFileName))
	t.Setenv("COPPERMIND_SCOPE", "platform/env")
	if sc, err := Resolve("", subDir, repoRoot); err != nil || sc != "platform/env" {
		t.Fatalf("expected env override platform/env, got %q %v", sc, err)
	}
	if sc, err := Resolve("platform/explicit", subDir, repoRoot); err != nil || sc != "platform/explicit" {
		t.Fatalf("expected explicit override platform/explicit, got %q %v", sc, err)
	}
}
