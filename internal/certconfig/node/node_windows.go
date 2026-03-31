//go:build windows

package node

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/certconfig/shared"
)

type windowsTrustConfigurator struct {
	bundlePath string
}

func newTrustConfigurator(bundlePath string) trustConfigurator {
	return &windowsTrustConfigurator{
		bundlePath: bundlePath,
	}
}

func (c *windowsTrustConfigurator) Install(ctx context.Context) error {
	return shared.RunPowerShellAsCurrentUser(
		ctx,
		fmt.Sprintf(
			"[Environment]::SetEnvironmentVariable('NODE_EXTRA_CA_CERTS', '%s', 'User')",
			shared.EscapePowerShellSingleQuoted(c.bundlePath),
		),
	)
}

func (c *windowsTrustConfigurator) Uninstall(ctx context.Context) error {
	original := ""
	if data, err := os.ReadFile(originalExtraCACertsPath()); err == nil {
		original = strings.TrimSpace(string(data))
	}
	// Saved file deletion is handled by Configurator.Uninstall.

	var script string
	if original != "" {
		script = fmt.Sprintf(
			"[Environment]::SetEnvironmentVariable('NODE_EXTRA_CA_CERTS', '%s', 'User')",
			shared.EscapePowerShellSingleQuoted(original),
		)
	} else {
		script = "[Environment]::SetEnvironmentVariable('NODE_EXTRA_CA_CERTS', $null, 'User')"
	}
	return shared.RunPowerShellAsCurrentUser(ctx, script)
}
