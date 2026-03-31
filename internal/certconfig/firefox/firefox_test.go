package firefox

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

func TestIsProfileDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "prefs.js"), []byte("// prefs"), 0o644); err != nil {
		t.Fatal(err)
	}

	if !isProfileDir(dir) {
		t.Fatal("expected prefs.js to mark directory as Firefox profile")
	}
}

func TestProfilesFiltersDirectories(t *testing.T) {
	cfg := platform.GetConfig()
	originalHome := cfg.HomeDir
	t.Cleanup(func() {
		cfg.HomeDir = originalHome
	})

	home := t.TempDir()
	cfg.HomeDir = home

	root := profilesRoot()
	if root == "" {
		t.Skip("unsupported OS for profilesRoot")
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

	got := profiles()
	if len(got) != 1 {
		t.Fatalf("expected 1 Firefox profile, got %d (%v)", len(got), got)
	}
	if got[0] != valid {
		t.Fatalf("expected profile %q, got %q", valid, got[0])
	}
}
