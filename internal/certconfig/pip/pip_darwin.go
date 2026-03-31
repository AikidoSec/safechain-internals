//go:build darwin

package pip

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/AikidoSec/safechain-internals/internal/certconfig/shared"
	"github.com/AikidoSec/safechain-internals/internal/platform"
)

var shellManagedBlockFormat = shared.ManagedBlockFormat{
	StartMarker: "# aikido-endpoint-pip-cert-config-start",
	EndMarker:   "# aikido-endpoint-pip-cert-config-end",
}

type darwinTrustConfigurator struct {
	targets []shared.DarwinShellTarget
}

func newTrustConfigurator(bundlePath string) trustConfigurator {
	comment := "# Allow pip to trust the SafeChain MITM CA while preserving user-provided roots."
	posix := comment + "\n" + fmt.Sprintf("export PIP_CERT=%q", bundlePath)
	fish := comment + "\n" + fmt.Sprintf("set -gx PIP_CERT %q", bundlePath)

	homeDir := platform.GetConfig().HomeDir

	return &darwinTrustConfigurator{
		targets: []shared.DarwinShellTarget{
			{Path: filepath.Join(homeDir, ".zshrc"), Body: posix},
			{Path: filepath.Join(homeDir, ".zprofile"), Body: posix},
			{Path: filepath.Join(homeDir, ".bash_profile"), Body: posix},
			{Path: filepath.Join(homeDir, ".bashrc"), Body: posix},
			{Path: filepath.Join(homeDir, ".profile"), Body: posix},
			{Path: filepath.Join(homeDir, ".config", "fish", "config.fish"), Body: fish, CreateIfMissing: true},
		},
	}
}

func (c *darwinTrustConfigurator) Install(_ context.Context) error {
	return shared.InstallDarwinShellTargets(c.targets, shellManagedBlockFormat)
}

func (c *darwinTrustConfigurator) Uninstall(_ context.Context) error {
	return shared.UninstallDarwinShellTargets(c.targets, shellManagedBlockFormat)
}
