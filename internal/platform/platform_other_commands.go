//go:build !darwin && !windows

package platform

import (
	"context"
	"os/exec"

	"github.com/AikidoSec/safechain-internals/internal/utils"
)

// RunAsCurrentUserWithPathEnv runs a command in the current process context on
// platforms where the daemon already runs as the target user.
func RunAsCurrentUserWithPathEnv(ctx context.Context, binaryPath string, args ...string) (string, error) {
	return utils.RunCommand(ctx, binaryPath, args...)
}

// CommandAsCurrentUserWithPathEnv builds a long-lived command for platforms
// where the daemon already runs in the target user context.
func CommandAsCurrentUserWithPathEnv(ctx context.Context, binaryPath string, args ...string) (*exec.Cmd, error) {
	return exec.CommandContext(ctx, binaryPath, args...), nil
}
