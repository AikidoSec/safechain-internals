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

var pipShellManagedBlockFormat = managedBlockFormat{
	startMarker: "# aikido-endpoint-pip-cert-config-start",
	endMarker:   "# aikido-endpoint-pip-cert-config-end",
}

type darwinPipTrustConfigurator struct {
	targets []darwinShellTarget
}

func newPipTrustConfigurator(bundlePath string) pipTrustConfigurator {
	comment := "# Allow Python package managers to trust the SafeChain MITM CA while preserving user-provided roots."
	posix := comment + "\n" + fmt.Sprintf(
		"export %s=%q\nexport %s=%q\nexport %s=%q\nexport %s=true",
		pipCertEnvVar,
		bundlePath,
		requestsCABundleEnvVar,
		bundlePath,
		poetryPyPICertEnvVar,
		bundlePath,
		uvNativeTLSEnvVar,
	)
	fish := comment + "\n" + fmt.Sprintf(
		"set -gx %s %q\nset -gx %s %q\nset -gx %s %q\nset -gx %s true",
		pipCertEnvVar,
		bundlePath,
		requestsCABundleEnvVar,
		bundlePath,
		poetryPyPICertEnvVar,
		bundlePath,
		uvNativeTLSEnvVar,
	)

	return &darwinPipTrustConfigurator{
		targets: []darwinShellTarget{
			{path: filepath.Join(platform.GetConfig().HomeDir, ".zshrc"), body: posix},
			{path: filepath.Join(platform.GetConfig().HomeDir, ".zprofile"), body: posix},
			{path: filepath.Join(platform.GetConfig().HomeDir, ".bash_profile"), body: posix},
			{path: filepath.Join(platform.GetConfig().HomeDir, ".bashrc"), body: posix},
			{path: filepath.Join(platform.GetConfig().HomeDir, ".profile"), body: posix},
			{path: filepath.Join(platform.GetConfig().HomeDir, ".config", "fish", "config.fish"), body: fish, createIfMissing: true},
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
		if err := writeManagedBlock(target.path, target.body, 0o644, pipShellManagedBlockFormat); err != nil {
			return err
		}
	}
	return nil
}

func (c *darwinPipTrustConfigurator) Uninstall(_ context.Context) error {
	for _, target := range c.targets {
		if err := utils.RemoveManagedBlock(target.path, 0o644, pipShellManagedBlockFormat.startMarker, pipShellManagedBlockFormat.endMarker); err != nil {
			return err
		}
	}
	return nil
}

func (c *darwinPipTrustConfigurator) NeedsRepair(_ context.Context) bool {
	for _, target := range c.targets {
		present, err := hasManagedBlock(target.path, pipShellManagedBlockFormat)
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
