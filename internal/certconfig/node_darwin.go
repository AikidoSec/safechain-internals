//go:build darwin

package certconfig

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

type darwinNodeTrustConfigurator struct {
	targets []darwinShellTarget
}

type darwinShellTarget struct {
	path string
	body string
}

func newNodeTrustConfigurator(bundlePath string) nodeTrustConfigurator {
	return &darwinNodeTrustConfigurator{
		targets: darwinShellTargets(bundlePath),
	}
}

func (c *darwinNodeTrustConfigurator) Install(_ context.Context) error {
	for _, target := range c.targets {
		if _, err := os.Stat(target.path); os.IsNotExist(err) {
			if filepath.Base(target.path) != "config.fish" {
				continue
			}
			if err := os.MkdirAll(filepath.Dir(target.path), 0o755); err != nil {
				return fmt.Errorf("failed to create fish config dir for %s: %w", target.path, err)
			}
		} else if err != nil {
			return fmt.Errorf("failed to stat %s: %w", target.path, err)
		}
		if err := writeManagedBlock(target.path, target.body, 0o644, shellManagedBlockFormat); err != nil {
			return err
		}
	}
	return nil
}

func (c *darwinNodeTrustConfigurator) Uninstall(_ context.Context) error {
	for _, target := range c.targets {
		if err := removeManagedBlock(target.path, 0o644, shellManagedBlockFormat); err != nil {
			return err
		}
	}
	return nil
}

func darwinShellTargets(bundlePath string) []darwinShellTarget {
	homeDir := platform.GetConfig().HomeDir

	comment := "# Allow Node.js tooling to trust the SafeChain MITM CA while preserving public roots."

	return []darwinShellTarget{
		{
			path: filepath.Join(homeDir, ".zshrc"),
			body: comment + "\n" + shellExportLine("NODE_EXTRA_CA_CERTS", bundlePath),
		},
		{
			path: filepath.Join(homeDir, ".zprofile"),
			body: comment + "\n" + shellExportLine("NODE_EXTRA_CA_CERTS", bundlePath),
		},
		{
			path: filepath.Join(homeDir, ".bash_profile"),
			body: comment + "\n" + shellExportLine("NODE_EXTRA_CA_CERTS", bundlePath),
		},
		{
			path: filepath.Join(homeDir, ".bashrc"),
			body: comment + "\n" + shellExportLine("NODE_EXTRA_CA_CERTS", bundlePath),
		},
		{
			path: filepath.Join(homeDir, ".profile"),
			body: comment + "\n" + shellExportLine("NODE_EXTRA_CA_CERTS", bundlePath),
		},
		{
			path: filepath.Join(homeDir, ".config", "fish", "config.fish"),
			body: comment + "\n" + fishSetLine("NODE_EXTRA_CA_CERTS", bundlePath),
		},
	}
}

func shellExportLine(name string, value string) string {
	return fmt.Sprintf("export %s=%q", name, value)
}

func fishSetLine(name string, value string) string {
	return fmt.Sprintf("set -gx %s %q", name, value)
}

var shellManagedBlockFormat = managedBlockFormat{
	startMarker: "# aikido-cert-config-start",
	endMarker:   "# aikido-cert-config-end",
}

func shellProfilePaths() []string {
	homeDir := platform.GetConfig().HomeDir
	return []string{
		filepath.Join(homeDir, ".zshrc"),
		filepath.Join(homeDir, ".zprofile"),
		filepath.Join(homeDir, ".bash_profile"),
		filepath.Join(homeDir, ".bashrc"),
		filepath.Join(homeDir, ".profile"),
	}
}
