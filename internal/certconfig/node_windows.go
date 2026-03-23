//go:build windows

package certconfig

import (
	"context"
	"fmt"
	"os"
	"strings"
)

type windowsNodeTrustConfigurator struct {
	bundlePath string
}

func newNodeTrustConfigurator(bundlePath string) nodeTrustConfigurator {
	return &windowsNodeTrustConfigurator{
		bundlePath: bundlePath,
	}
}

func (c *windowsNodeTrustConfigurator) Install(ctx context.Context) error {
	return runPowerShellAsCurrentUser(
		ctx,
		fmt.Sprintf(
			"[Environment]::SetEnvironmentVariable('NODE_EXTRA_CA_CERTS', '%s', 'User')",
			escapePowerShellSingleQuoted(c.bundlePath),
		),
	)
}

func (c *windowsNodeTrustConfigurator) Uninstall(ctx context.Context) error {
	original := ""
	if data, err := os.ReadFile(originalNodeExtraCACertsPath()); err == nil {
		original = strings.TrimSpace(string(data))
	}
	// Saved file deletion is handled by nodeConfigurator.Uninstall.

	var script string
	if original != "" {
		script = fmt.Sprintf(
			"[Environment]::SetEnvironmentVariable('NODE_EXTRA_CA_CERTS', '%s', 'User')",
			escapePowerShellSingleQuoted(original),
		)
	} else {
		script = "[Environment]::SetEnvironmentVariable('NODE_EXTRA_CA_CERTS', $null, 'User')"
	}
	return runPowerShellAsCurrentUser(ctx, script)
}

func runPowerShellAsCurrentUser(ctx context.Context, script string) error {
	_, err := platform.RunAsCurrentUser(ctx, "powershell", []string{
		"-NoProfile",
		"-NonInteractive",
		"-Command",
		script,
	})
	return err
}

func escapePowerShellSingleQuoted(value string) string {
	return strings.ReplaceAll(value, "'", "''")
}
