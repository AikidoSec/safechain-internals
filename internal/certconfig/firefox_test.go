package certconfig

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

func TestIsFirefoxProfileDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "prefs.js"), []byte("// prefs"), 0o644); err != nil {
		t.Fatal(err)
	}

	if !isFirefoxProfileDir(dir) {
		t.Fatal("expected prefs.js to mark directory as Firefox profile")
	}
}

func TestFirefoxProfilesFiltersDirectories(t *testing.T) {
	cfg := platform.GetConfig()
	originalHome := cfg.HomeDir
	t.Cleanup(func() {
		cfg.HomeDir = originalHome
	})

	home := t.TempDir()
	cfg.HomeDir = home

	root := firefoxProfilesRoot()
	if root == "" {
		t.Skip("unsupported OS for firefoxProfilesRoot")
	}

	valid := filepath.Join(root, "abcd1234.default-release")
	invalidNoDot := filepath.Join(root, "notaprofile")
	invalidNoMarkers := filepath.Join(root, "abcd1234.empty")

	for _, dir := range []string{valid, invalidNoDot, invalidNoMarkers} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(valid, "prefs.js"), []byte("// prefs"), 0o644); err != nil {
		t.Fatal(err)
	}

	got := firefoxProfiles()
	if len(got) != 1 {
		t.Fatalf("expected 1 Firefox profile, got %d (%v)", len(got), got)
	}
	if got[0] != valid {
		t.Fatalf("expected profile %q, got %q", valid, got[0])
	}
}

func TestFirefoxConfiguratorNeedsRepairFalseWhenNoProfiles(t *testing.T) {
	cfg := platform.GetConfig()
	originalHome := cfg.HomeDir
	t.Cleanup(func() { cfg.HomeDir = originalHome })
	cfg.HomeDir = t.TempDir()

	if newFirefoxConfigurator().NeedsRepair(t.Context()) {
		t.Fatal("expected NeedsRepair=false when no Firefox profiles exist")
	}
}

func TestFirefoxConfiguratorNeedsRepairFalseWhenBlockPresent(t *testing.T) {
	cfg := platform.GetConfig()
	originalHome := cfg.HomeDir
	t.Cleanup(func() { cfg.HomeDir = originalHome })
	cfg.HomeDir = t.TempDir()

	root := firefoxProfilesRoot()
	if root == "" {
		t.Skip("unsupported OS for firefoxProfilesRoot")
	}
	profile := filepath.Join(root, "abc123.default")
	if err := os.MkdirAll(profile, 0o755); err != nil {
		t.Fatal(err)
	}
	// Mark directory as a Firefox profile.
	if err := os.WriteFile(filepath.Join(profile, "prefs.js"), []byte("// prefs\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := newFirefoxConfigurator().Install(t.Context()); err != nil {
		t.Fatalf("Install failed: %v", err)
	}

	if newFirefoxConfigurator().NeedsRepair(t.Context()) {
		t.Fatal("expected NeedsRepair=false when managed block is present in user.js")
	}
}

func TestFirefoxConfiguratorNeedsRepairWhenBlockMissing(t *testing.T) {
	cfg := platform.GetConfig()
	originalHome := cfg.HomeDir
	t.Cleanup(func() { cfg.HomeDir = originalHome })
	cfg.HomeDir = t.TempDir()

	root := firefoxProfilesRoot()
	if root == "" {
		t.Skip("unsupported OS for firefoxProfilesRoot")
	}
	profile := filepath.Join(root, "abc123.default")
	if err := os.MkdirAll(profile, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profile, "prefs.js"), []byte("// prefs\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// user.js exists but has no managed block.
	if err := os.WriteFile(filepath.Join(profile, "user.js"), []byte("// user prefs\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if !newFirefoxConfigurator().NeedsRepair(t.Context()) {
		t.Fatal("expected NeedsRepair=true when user.js exists but managed block is absent")
	}
}
