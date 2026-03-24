//go:build windows

package certconfig

import (
	"context"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

func runPipCertLookup(ctx context.Context) (string, error) {
	return platform.RunAsCurrentUser(ctx, "powershell", []string{
		"-NoProfile",
		"-NonInteractive",
		"-Command",
		`if ($env:PIP_CERT) { [Console]::Write($env:PIP_CERT) } elseif ($env:REQUESTS_CA_BUNDLE) { [Console]::Write($env:REQUESTS_CA_BUNDLE) } elseif ($env:SSL_CERT_FILE) { [Console]::Write($env:SSL_CERT_FILE) }`,
	})
}
