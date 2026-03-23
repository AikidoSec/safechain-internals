//go:build windows

package certconfig

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

type windowsNodeTrustConfigurator struct {
	bundlePath string
}

func newNodeTrustConfigurator(bundlePath string) nodeTrustConfigurator {
	return &windowsNodeTrustConfigurator{
		bundlePath: bundlePath,
	}
}

func originalNodeExtraCACertsPath() string {
	return filepath.Join(platform.GetRunDir(), "endpoint-protection-node-original-extra-ca-certs.txt")
}

func (c *windowsNodeTrustConfigurator) Install(ctx context.Context) error {
	// Save the current value before overwriting so Uninstall can restore it.
	existing, err := runNodeExtraCACertsLookup(ctx)
	if err != nil {
		log.Printf("Warning: failed to read existing NODE_EXTRA_CA_CERTS before update: %v", err)
		return fmt.Errorf("read existing NODE_EXTRA_CA_CERTS: %w", err)
	}
	if err := os.WriteFile(originalNodeExtraCACertsPath(), []byte(strings.TrimSpace(existing)), 0o600); err != nil {
		log.Printf("Warning: failed to persist existing NODE_EXTRA_CA_CERTS before update: %v", err)
		return fmt.Errorf("persist existing NODE_EXTRA_CA_CERTS: %w", err)
	}

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
	_ = os.Remove(originalNodeExtraCACertsPath())

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
