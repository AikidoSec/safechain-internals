//go:build windows

package shared

import (
	"context"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

func RunPowerShellAsCurrentUser(ctx context.Context, script string) error {
	_, err := platform.RunAsCurrentUser(ctx, "powershell", []string{
		"-NoProfile",
		"-NonInteractive",
		"-Command",
		script,
	})
	return err
}

func EscapePowerShellSingleQuoted(value string) string {
	return strings.ReplaceAll(value, "'", "''")
}
