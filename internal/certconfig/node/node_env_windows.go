//go:build windows

package node

import (
	"context"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

func runExtraCACertsLookup(ctx context.Context) (string, error) {
	return platform.RunAsCurrentUser(ctx, "powershell", []string{
		"-NoProfile",
		"-NonInteractive",
		"-Command",
		`[Console]::Write($env:NODE_EXTRA_CA_CERTS)`,
	})
}
