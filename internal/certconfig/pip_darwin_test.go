//go:build darwin

package certconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

func TestNewPipTrustConfiguratorManagedBlockContent(t *testing.T) {
	const bundle = "/some/bundle.pem"
	cfg := platform.GetConfig()
	originalHome := cfg.HomeDir
	t.Cleanup(func() {
		cfg.HomeDir = originalHome
	})
	cfg.HomeDir = "/tmp/test-home"
	configurator := newPipTrustConfigurator(bundle).(*darwinPipTrustConfigurator)

	// Every shell target should export all required vars.
	requiredPosix := []string{
		`export PIP_CERT=`,
		`export REQUESTS_CA_BUNDLE=`,
		`export POETRY_CERTIFICATES_PYPI_CERT=`,
		`export UV_NATIVE_TLS=true`,
		bundle,
	}
	requiredFish := []string{
		`set -gx PIP_CERT`,
		`set -gx REQUESTS_CA_BUNDLE`,
		`set -gx POETRY_CERTIFICATES_PYPI_CERT`,
		`set -gx UV_NATIVE_TLS true`,
		bundle,
	}

	for _, target := range configurator.targets {
		isFish := strings.HasSuffix(target.path, "config.fish")
		required := requiredPosix
		if isFish {
			required = requiredFish
		}
		for _, want := range required {
			if !strings.Contains(target.body, want) {
				t.Errorf("shell target %s: body missing %q\ngot:\n%s", target.path, want, target.body)
			}
		}
	}
}

func TestNewPipTrustConfiguratorDoesNotSetSSLCertFile(t *testing.T) {
	cfg := platform.GetConfig()
	originalHome := cfg.HomeDir
	t.Cleanup(func() {
		cfg.HomeDir = originalHome
	})
	cfg.HomeDir = "/tmp/test-home"
	configurator := newPipTrustConfigurator("/some/bundle.pem").(*darwinPipTrustConfigurator)
	for _, target := range configurator.targets {
		if strings.Contains(target.body, "SSL_CERT_FILE") {
			t.Errorf("shell target %s: body must not set SSL_CERT_FILE (too broad)\ngot:\n%s", target.path, target.body)
		}
	}
}

func TestPipConfiguratorNeedsRepairWhenBundleMissing(t *testing.T) {
	cfg := platform.GetConfig()
	origRunDir, origHomeDir := cfg.RunDir, cfg.HomeDir
	t.Cleanup(func() {
		cfg.RunDir = origRunDir
		cfg.HomeDir = origHomeDir
	})
	cfg.RunDir = t.TempDir()
	cfg.HomeDir = t.TempDir()

	if !newPipConfigurator().NeedsRepair(t.Context()) {
		t.Fatal("expected NeedsRepair=true when pip combined CA bundle is missing")
	}
}

func TestPipConfiguratorNeedsRepairFalseWhenInstalled(t *testing.T) {
	cfg := platform.GetConfig()
	origRunDir, origHomeDir := cfg.RunDir, cfg.HomeDir
	t.Cleanup(func() {
		cfg.RunDir = origRunDir
		cfg.HomeDir = origHomeDir
	})
	cfg.RunDir = t.TempDir()
	cfg.HomeDir = t.TempDir()

	bundlePath := pipCombinedCaBundlePath()
	if err := os.WriteFile(bundlePath, []byte(mustCreateTestCertificatePEM(t, "pip-ca")), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := newPipTrustConfigurator(bundlePath).Install(t.Context()); err != nil {
		t.Fatalf("Install failed: %v", err)
	}

	if newPipConfigurator().NeedsRepair(t.Context()) {
		t.Fatal("expected NeedsRepair=false after install")
	}
}

func TestPipConfiguratorNeedsRepairWhenShellBlockMissing(t *testing.T) {
	cfg := platform.GetConfig()
	origRunDir, origHomeDir := cfg.RunDir, cfg.HomeDir
	t.Cleanup(func() {
		cfg.RunDir = origRunDir
		cfg.HomeDir = origHomeDir
	})
	cfg.RunDir = t.TempDir()
	cfg.HomeDir = t.TempDir()

	bundlePath := pipCombinedCaBundlePath()
	if err := os.WriteFile(bundlePath, []byte(mustCreateTestCertificatePEM(t, "pip-shell")), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create .zshrc without the managed block — NeedsRepair must detect the gap.
	if err := os.WriteFile(filepath.Join(cfg.HomeDir, ".zshrc"), []byte("# existing zshrc\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if !newPipConfigurator().NeedsRepair(t.Context()) {
		t.Fatal("expected NeedsRepair=true when shell config exists but managed block is absent")
	}
}
