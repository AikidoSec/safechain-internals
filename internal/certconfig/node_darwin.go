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

type darwinShellKind int

const (
	posixShell darwinShellKind = iota
	fishShell
)

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
	targets := []struct {
		path string
		kind darwinShellKind
	}{
		{path: filepath.Join(homeDir, ".zshrc"), kind: posixShell},
		{path: filepath.Join(homeDir, ".zprofile"), kind: posixShell},
		{path: filepath.Join(homeDir, ".bash_profile"), kind: posixShell},
		{path: filepath.Join(homeDir, ".bashrc"), kind: posixShell},
		{path: filepath.Join(homeDir, ".profile"), kind: posixShell},
		{path: filepath.Join(homeDir, ".config", "fish", "config.fish"), kind: fishShell},
	}

	shellTargets := make([]darwinShellTarget, 0, len(targets))
	for _, target := range targets {
		shellTargets = append(shellTargets, darwinShellTarget{
			path: target.path,
			body: shellEnvBlockBody(comment, target.kind, "NODE_EXTRA_CA_CERTS", bundlePath),
		})
	}

	return shellTargets
}

func shellEnvBlockBody(comment string, kind darwinShellKind, name string, value string) string {
	switch kind {
	case fishShell:
		return comment + "\n" + fishSetLine(name, value)
	default:
		return comment + "\n" + shellExportLine(name, value)
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
