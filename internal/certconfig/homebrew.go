//go:build darwin

package certconfig

import (
	"context"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/platform"
	"github.com/AikidoSec/safechain-internals/internal/proxy"
)

type homebrewConfigurator struct{}

func newHomebrewConfigurator() Configurator { return &homebrewConfigurator{} }

func (c *homebrewConfigurator) Name() string { return "homebrew" }

func (c *homebrewConfigurator) Install(ctx context.Context) error {
	return syncHomebrewCACerts(ctx)
}

func (c *homebrewConfigurator) NeedsRepair(_ context.Context) bool {
	brewPath := findBrew()
	if brewPath == "" {
		return false
	}

	bundlePath := filepath.Join(filepath.Dir(filepath.Dir(brewPath)), "etc", "ca-certificates", "cert.pem")
	bundleData, err := os.ReadFile(bundlePath)
	if err != nil {
		return true
	}

	safeChainCA, err := os.ReadFile(proxy.GetCaCertPath())
	if err != nil {
		return true
	}

	return !strings.Contains(string(bundleData), strings.TrimSpace(string(safeChainCA)))
}

func (c *homebrewConfigurator) Uninstall(_ context.Context) error {
	// brew postinstall ca-certificates re-merges the macOS keychain into
	// Homebrew's CA bundle. On uninstall the SafeChain CA is removed from the
	// keychain by proxy.UninstallProxyCA, so there is nothing to clean up here.
	// Running brew on teardown is slow and would block later configurators.
	return nil
}

// knownBrewPaths lists the canonical Homebrew binary locations.
// The daemon runs as root and its PATH does not include Homebrew directories,
// so exec.LookPath("brew") would fail even when brew is installed.
var knownBrewPaths = []string{
	"/opt/homebrew/bin/brew", // Apple Silicon
	"/usr/local/bin/brew",    // Intel
}

// syncHomebrewCACerts runs `brew postinstall ca-certificates`, which merges the
// macOS system keychain into Homebrew's shared OpenSSL CA bundle at
// /opt/homebrew/etc/ca-certificates/. This covers all Homebrew-installed tools
// that link against Homebrew's OpenSSL (Ruby, curl, git, Claude CLI, etc.).
//
// The command is a no-op if Homebrew or the ca-certificates package is not
// installed — both cases are logged and treated as non-fatal.
func syncHomebrewCACerts(ctx context.Context) error {
	brewPath := findBrew()
	if brewPath == "" {
		log.Printf("homebrew: brew not found, skipping ca-certificates sync")
		return nil
	}

	out, err := platform.RunAsCurrentUserWithPathEnv(ctx, brewPath, "postinstall", "ca-certificates")
	if err != nil {
		log.Printf("homebrew: brew postinstall ca-certificates failed (likely not installed), skipping: %v (output: %s)", err, out)
		return nil
	}
	return nil
}

func findBrew() string {
	for _, p := range knownBrewPaths {
		if _, err := exec.LookPath(p); err == nil {
			return p
		}
	}
	return ""
}
