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

type darwinPipTrustConfigurator struct {
	targets []darwinShellTarget
}

func newPipTrustConfigurator(bundlePath string) pipTrustConfigurator {
	comment := "# Allow pip to trust the SafeChain MITM CA while preserving user-provided roots."
	posix := comment + "\n" + fmt.Sprintf("export PIP_CERT=%q", bundlePath)
	fish := comment + "\n" + fmt.Sprintf("set -gx PIP_CERT %q", bundlePath)

	homeDir := platform.GetConfig().HomeDir

	return &darwinPipTrustConfigurator{
		targets: []darwinShellTarget{
			{path: filepath.Join(homeDir, ".zshrc"), body: posix},
			{path: filepath.Join(homeDir, ".zprofile"), body: posix},
			{path: filepath.Join(homeDir, ".bash_profile"), body: posix},
			{path: filepath.Join(homeDir, ".bashrc"), body: posix},
			{path: filepath.Join(homeDir, ".profile"), body: posix},
			{path: filepath.Join(homeDir, ".config", "fish", "config.fish"), body: fish, createIfMissing: true},
		},
	}
}

func (c *darwinPipTrustConfigurator) Install(_ context.Context) error {
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

func (c *darwinPipTrustConfigurator) Uninstall(_ context.Context) error {
	for _, target := range c.targets {
		if err := utils.RemoveManagedBlock(target.path, 0o644, shellManagedBlockFormat.startMarker, shellManagedBlockFormat.endMarker); err != nil {
			return err
		}
	}
	return nil
}
