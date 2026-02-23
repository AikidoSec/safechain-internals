package npm

import (
	"context"
	"runtime"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

const (
	unixBinaryName    = "npm"
	windowsBinaryName = "npm.cmd"
)

func binaryName() string {
	if runtime.GOOS == "windows" {
		return windowsBinaryName
	}
	return unixBinaryName
}

func runNpm(ctx context.Context, npmPath string, args ...string) (string, error) {
	return platform.RunAsCurrentUserWithPathEnv(ctx, npmPath, args...)
}

func getVersion(ctx context.Context, path string) (string, error) {
	quietCtx := context.WithValue(ctx, "disable_logging", true)
	output, err := runNpm(quietCtx, path, "--version")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(output), nil
}
