//go:build darwin

package certconfig

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AikidoSec/safechain-internals/internal/platform"
	"github.com/AikidoSec/safechain-internals/internal/proxy"
)

func TestHomebrewConfiguratorNeedsRepairWhenBundleMissing(t *testing.T) {
	brewRoot := t.TempDir()
	brewBinDir := filepath.Join(brewRoot, "bin")
	if err := os.MkdirAll(brewBinDir, 0o755); err != nil {
		t.Fatal(err)
	}

	brewPath := filepath.Join(brewBinDir, "brew")
	if err := os.WriteFile(brewPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	originalBrewPaths := knownBrewPaths
	knownBrewPaths = []string{brewPath}
	t.Cleanup(func() {
		knownBrewPaths = originalBrewPaths
	})

	runDir := t.TempDir()
	platform.GetConfig().RunDir = runDir

	caPath := proxy.GetCaCertPath()
	if err := os.MkdirAll(filepath.Dir(caPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, []byte(mustCreateTestCertificatePEM(t, "homebrew-missing")), 0o644); err != nil {
		t.Fatal(err)
	}

	if !newHomebrewConfigurator().NeedsRepair(t.Context()) {
		t.Fatal("expected Homebrew trust repair to be required when bundle is missing")
	}
}

func TestHomebrewConfiguratorNeedsRepairFalseWhenBundleContainsSafeChainCA(t *testing.T) {
	brewRoot := t.TempDir()
	brewBinDir := filepath.Join(brewRoot, "bin")
	brewEtcDir := filepath.Join(brewRoot, "etc", "ca-certificates")
	if err := os.MkdirAll(brewBinDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(brewEtcDir, 0o755); err != nil {
		t.Fatal(err)
	}

	brewPath := filepath.Join(brewBinDir, "brew")
	if err := os.WriteFile(brewPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	originalBrewPaths := knownBrewPaths
	knownBrewPaths = []string{brewPath}
	t.Cleanup(func() {
		knownBrewPaths = originalBrewPaths
	})

	runDir := t.TempDir()
	platform.GetConfig().RunDir = runDir

	caPayload := mustCreateTestCertificatePEM(t, "homebrew-present")
	caPath := proxy.GetCaCertPath()
	if err := os.MkdirAll(filepath.Dir(caPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, []byte(caPayload), 0o644); err != nil {
		t.Fatal(err)
	}

	bundlePath := filepath.Join(brewEtcDir, "cert.pem")
	if err := os.WriteFile(bundlePath, []byte(caPayload+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if newHomebrewConfigurator().NeedsRepair(t.Context()) {
		t.Fatal("expected Homebrew trust to be healthy when bundle contains SafeChain CA")
	}
}
