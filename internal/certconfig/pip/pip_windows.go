//go:build windows

package pip

import (
	"context"
	"fmt"
	"os"

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
			"[Environment]::SetEnvironmentVariable('PIP_CERT', '%s', 'User')",
			shared.EscapePowerShellSingleQuoted(c.bundlePath),
		),
	)
}

func (c *windowsTrustConfigurator) Uninstall(ctx context.Context) error {
	original := CertSetting{}
	if data, err := os.ReadFile(originalCertPath()); err == nil {
		parsed, parseErr := parseSavedCertSetting(data)
		if parseErr == nil {
			original = parsed
		}
	}

	script := restoreWindowsEnvScript(original)
	return shared.RunPowerShellAsCurrentUser(ctx, script)
}

func restoreWindowsEnvScript(original CertSetting) string {
	path := shared.EscapePowerShellSingleQuoted(original.Path)

	switch original.EnvVar {
	case RequestsCABundleEnvVar:
		return fmt.Sprintf(
			"[Environment]::SetEnvironmentVariable('PIP_CERT', $null, 'User'); [Environment]::SetEnvironmentVariable('REQUESTS_CA_BUNDLE', '%s', 'User')",
			path,
		)
	case SSLCertFileEnvVar:
		return fmt.Sprintf(
			"[Environment]::SetEnvironmentVariable('PIP_CERT', $null, 'User'); [Environment]::SetEnvironmentVariable('SSL_CERT_FILE', '%s', 'User')",
			path,
		)
	case CertEnvVar:
		if original.Path != "" {
			return fmt.Sprintf(
				"[Environment]::SetEnvironmentVariable('PIP_CERT', '%s', 'User')",
				path,
			)
		}
	}

	return "[Environment]::SetEnvironmentVariable('PIP_CERT', $null, 'User')"
}
