//go:build windows

package certconfig

import (
	"context"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

func runPipCertLookup(ctx context.Context) (pipCertSetting, error) {
	out, err := platform.RunAsCurrentUser(ctx, "powershell", []string{
		"-NoProfile",
		"-NonInteractive",
		"-Command",
		`if ($env:PIP_CERT) { [Console]::Write('PIP_CERT:' + $env:PIP_CERT) } elseif ($env:REQUESTS_CA_BUNDLE) { [Console]::Write('REQUESTS_CA_BUNDLE:' + $env:REQUESTS_CA_BUNDLE) } elseif ($env:SSL_CERT_FILE) { [Console]::Write('SSL_CERT_FILE:' + $env:SSL_CERT_FILE) }`,
	})
	if err != nil {
		return pipCertSetting{}, err
	}
	return parsePipCertSettingString(out), nil
}
