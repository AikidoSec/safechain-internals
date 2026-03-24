//go:build windows

package certconfig

import (
	"context"
	"fmt"
	"os"
	"strings"
)

type windowsPipTrustConfigurator struct {
	bundlePath string
}

func newPipTrustConfigurator(bundlePath string) pipTrustConfigurator {
	return &windowsPipTrustConfigurator{
		bundlePath: bundlePath,
	}
}

func (c *windowsPipTrustConfigurator) Install(ctx context.Context) error {
	return runPowerShellAsCurrentUser(
		ctx,
		fmt.Sprintf(
			"[Environment]::SetEnvironmentVariable('PIP_CERT', '%s', 'User')",
			escapePowerShellSingleQuoted(c.bundlePath),
		),
	)
}

func (c *windowsPipTrustConfigurator) Uninstall(ctx context.Context) error {
	original := ""
	if data, err := os.ReadFile(originalPipCertPath()); err == nil {
		original = strings.TrimSpace(string(data))
	}

	var script string
	if original != "" {
		script = fmt.Sprintf(
			"[Environment]::SetEnvironmentVariable('PIP_CERT', '%s', 'User')",
			escapePowerShellSingleQuoted(original),
		)
	} else {
		script = "[Environment]::SetEnvironmentVariable('PIP_CERT', $null, 'User')"
	}
	return runPowerShellAsCurrentUser(ctx, script)
}
