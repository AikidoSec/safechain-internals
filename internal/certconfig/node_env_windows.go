//go:build windows

package certconfig

import (
	"context"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

func runNodeExtraCACertsLookup(ctx context.Context) (string, error) {
	return platform.RunAsCurrentUser(ctx, "powershell", []string{
		"-NoProfile",
		"-NonInteractive",
		"-Command",
		`[Console]::Write($env:NODE_EXTRA_CA_CERTS)`,
	})
}
