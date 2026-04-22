//go:build darwin

package certconfig

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

func TestGitConfiguratorNeedsRepairWhenBundleMissing(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	cfg := platform.GetConfig()
	origRunDir := cfg.RunDir
	t.Cleanup(func() { cfg.RunDir = origRunDir })
	cfg.RunDir = t.TempDir()

	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(t.TempDir(), ".gitconfig"))

	// No bundle file — NeedsRepair must return true.
	if !newGitConfigurator().NeedsRepair(t.Context()) {
		t.Fatal("expected NeedsRepair=true when git CA bundle is missing")
	}
}

func TestGitConfiguratorNeedsRepairWhenConfigUnset(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	cfg := platform.GetConfig()
	origRunDir := cfg.RunDir
	t.Cleanup(func() { cfg.RunDir = origRunDir })
	cfg.RunDir = t.TempDir()

	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(t.TempDir(), ".gitconfig"))

	// Bundle exists but http.sslCAInfo is not set in git config.
	bundlePath := gitCombinedCaBundlePath()
	if err := os.WriteFile(bundlePath, []byte(mustCreateTestCertificatePEM(t, "git-ca")), 0o644); err != nil {
		t.Fatal(err)
	}

	if !newGitConfigurator().NeedsRepair(t.Context()) {
		t.Fatal("expected NeedsRepair=true when http.sslCAInfo is not configured")
	}
}

func TestGitConfiguratorNeedsRepairFalseWhenConfigured(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	cfg := platform.GetConfig()
	origRunDir := cfg.RunDir
	t.Cleanup(func() { cfg.RunDir = origRunDir })
	cfg.RunDir = t.TempDir()

	gitConfig := filepath.Join(t.TempDir(), ".gitconfig")
	t.Setenv("GIT_CONFIG_GLOBAL", gitConfig)

	bundlePath := gitCombinedCaBundlePath()
	if err := os.WriteFile(bundlePath, []byte(mustCreateTestCertificatePEM(t, "git-ca")), 0o644); err != nil {
		t.Fatal(err)
	}

	// Write git config pointing at the bundle.
	if err := os.WriteFile(gitConfig, []byte("[http]\n\tsslCAInfo = "+bundlePath+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if newGitConfigurator().NeedsRepair(t.Context()) {
		t.Fatal("expected NeedsRepair=false when git config points to the bundle")
	}
}

func TestGitConfiguratorNeedsRepairWhenConfigPointsElsewhere(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	cfg := platform.GetConfig()
	origRunDir := cfg.RunDir
	t.Cleanup(func() { cfg.RunDir = origRunDir })
	cfg.RunDir = t.TempDir()

	gitConfig := filepath.Join(t.TempDir(), ".gitconfig")
	t.Setenv("GIT_CONFIG_GLOBAL", gitConfig)

	bundlePath := gitCombinedCaBundlePath()
	if err := os.WriteFile(bundlePath, []byte(mustCreateTestCertificatePEM(t, "git-ca")), 0o644); err != nil {
		t.Fatal(err)
	}

	// Config points to a different path.
	if err := os.WriteFile(gitConfig, []byte("[http]\n\tsslCAInfo = /some/other/ca.pem\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if !newGitConfigurator().NeedsRepair(t.Context()) {
		t.Fatal("expected NeedsRepair=true when http.sslCAInfo points to a different bundle")
	}
}
