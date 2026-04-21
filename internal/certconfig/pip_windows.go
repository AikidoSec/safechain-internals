//go:build windows

package certconfig

import (
	"context"
	"fmt"
	"os"
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
	original := pipCertSetting{}
	if data, err := os.ReadFile(originalPipCertPath()); err == nil {
		parsed, parseErr := parseSavedPipCertSetting(data)
		if parseErr == nil {
			original = parsed
		}
	}

	script := restoreWindowsPipEnvScript(original)
	return runPowerShellAsCurrentUser(ctx, script)
}

func (c *windowsPipTrustConfigurator) NeedsRepair(ctx context.Context) bool {
	current, err := runPipCertLookup(ctx)
	if err != nil {
		return false
	}
	return current.Path != c.bundlePath
}

func restoreWindowsPipEnvScript(original pipCertSetting) string {
	path := escapePowerShellSingleQuoted(original.Path)

	switch original.EnvVar {
	case requestsCABundleEnvVar:
		return fmt.Sprintf(
			"[Environment]::SetEnvironmentVariable('PIP_CERT', $null, 'User'); [Environment]::SetEnvironmentVariable('REQUESTS_CA_BUNDLE', '%s', 'User')",
			path,
		)
	case sslCertFileEnvVar:
		return fmt.Sprintf(
			"[Environment]::SetEnvironmentVariable('PIP_CERT', $null, 'User'); [Environment]::SetEnvironmentVariable('SSL_CERT_FILE', '%s', 'User')",
			path,
		)
	case pipCertEnvVar:
		if original.Path != "" {
			return fmt.Sprintf(
				"[Environment]::SetEnvironmentVariable('PIP_CERT', '%s', 'User')",
				path,
			)
		}
	}

	return "[Environment]::SetEnvironmentVariable('PIP_CERT', $null, 'User')"
}
