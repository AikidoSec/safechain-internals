//go:build darwin

package certconfig

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/AikidoSec/safechain-internals/internal/platform"
	"github.com/AikidoSec/safechain-internals/internal/utils"
)

type darwinNodeTrustConfigurator struct {
	targets []darwinShellTarget
}

type darwinShellTarget struct {
	path            string
	body            string
	createIfMissing bool
}

func newNodeTrustConfigurator(bundlePath string) nodeTrustConfigurator {
	return &darwinNodeTrustConfigurator{
		targets: darwinShellTargets(bundlePath),
	}
}

func (c *darwinNodeTrustConfigurator) Install(_ context.Context) error {
	for _, target := range c.targets {
		if _, err := os.Stat(target.path); err != nil {
			if !os.IsNotExist(err) {
				return fmt.Errorf("failed to stat %s: %w", target.path, err)
			}
			if !target.createIfMissing {
				continue
			}
			if err := os.MkdirAll(filepath.Dir(target.path), 0o755); err != nil {
				return fmt.Errorf("failed to create config dir for %s: %w", target.path, err)
			}
		}
		if err := writeManagedBlock(target.path, target.body, 0o644, shellManagedBlockFormat); err != nil {
			return err
		}
	}
	return nil
}

func (c *darwinNodeTrustConfigurator) Uninstall(_ context.Context) error {
	for _, target := range c.targets {
		if err := utils.RemoveManagedBlock(target.path, 0o644, shellManagedBlockFormat.startMarker, shellManagedBlockFormat.endMarker); err != nil {
			return err
		}
	}
	return nil
}

func (c *darwinNodeTrustConfigurator) NeedsRepair(_ context.Context) bool {
	for _, target := range c.targets {
		present, err := hasManagedBlock(target.path, shellManagedBlockFormat)
		if err != nil {
			return true
		}
		if present {
			continue
		}
		if _, err := os.Stat(target.path); err == nil || target.createIfMissing {
			return true
		} else if !os.IsNotExist(err) {
			return true
		}
	}
	return false
}

func darwinShellTargets(bundlePath string) []darwinShellTarget {
	homeDir := platform.GetConfig().HomeDir
	comment := "# Allow Node.js tooling to trust the SafeChain MITM CA while preserving public roots."
	posix := comment + "\n" + fmt.Sprintf("export NODE_EXTRA_CA_CERTS=%q", bundlePath)
	fish := comment + "\n" + fmt.Sprintf("set -gx NODE_EXTRA_CA_CERTS %q", bundlePath)

	return []darwinShellTarget{
		{path: filepath.Join(homeDir, ".zshrc"), body: posix},
		{path: filepath.Join(homeDir, ".zprofile"), body: posix},
		{path: filepath.Join(homeDir, ".bash_profile"), body: posix},
		{path: filepath.Join(homeDir, ".bashrc"), body: posix},
		{path: filepath.Join(homeDir, ".profile"), body: posix},
		{path: filepath.Join(homeDir, ".config", "fish", "config.fish"), body: fish, createIfMissing: true},
	}
}

var shellManagedBlockFormat = managedBlockFormat{
	startMarker: "# aikido-endpoint-cert-config-start",
	endMarker:   "# aikido-endpoint-cert-config-end",
}
