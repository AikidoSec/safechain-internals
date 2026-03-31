//go:build darwin

package node

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/AikidoSec/safechain-internals/internal/certconfig/shared"
	"github.com/AikidoSec/safechain-internals/internal/platform"
)

type darwinTrustConfigurator struct {
	targets []shared.DarwinShellTarget
}

var shellManagedBlockFormat = shared.ManagedBlockFormat{
	StartMarker: "# aikido-endpoint-cert-config-start",
	EndMarker:   "# aikido-endpoint-cert-config-end",
}

func newTrustConfigurator(bundlePath string) trustConfigurator {
	return &darwinTrustConfigurator{
		targets: darwinShellTargets(bundlePath),
	}
}

func (c *darwinTrustConfigurator) Install(_ context.Context) error {
	return shared.InstallDarwinShellTargets(c.targets, shellManagedBlockFormat)
}

func (c *darwinTrustConfigurator) Uninstall(_ context.Context) error {
	return shared.UninstallDarwinShellTargets(c.targets, shellManagedBlockFormat)
}

func darwinShellTargets(bundlePath string) []shared.DarwinShellTarget {
	homeDir := platform.GetConfig().HomeDir
	comment := "# Allow Node.js tooling to trust the SafeChain MITM CA while preserving public roots."
	posix := comment + "\n" + fmt.Sprintf("export NODE_EXTRA_CA_CERTS=%q", bundlePath)
	fish := comment + "\n" + fmt.Sprintf("set -gx NODE_EXTRA_CA_CERTS %q", bundlePath)

	return []shared.DarwinShellTarget{
		{Path: filepath.Join(homeDir, ".zshrc"), Body: posix},
		{Path: filepath.Join(homeDir, ".zprofile"), Body: posix},
		{Path: filepath.Join(homeDir, ".bash_profile"), Body: posix},
		{Path: filepath.Join(homeDir, ".bashrc"), Body: posix},
		{Path: filepath.Join(homeDir, ".profile"), Body: posix},
		{Path: filepath.Join(homeDir, ".config", "fish", "config.fish"), Body: fish, CreateIfMissing: true},
	}
}
