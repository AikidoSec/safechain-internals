package npm

import (
	"context"
	"os"
	"path/filepath"
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

func run(ctx context.Context, npmPath string, args ...string) (string, error) {
	binDir := filepath.Dir(npmPath)
	pathEnv := binDir

	resolved, err := filepath.EvalSymlinks(npmPath)
	if err == nil {
		resolvedDir := filepath.Dir(resolved)
		if resolvedDir != binDir {
			pathEnv = binDir + string(os.PathListSeparator) + resolvedDir
		}
	}

	pathEnv = pathEnv + string(os.PathListSeparator) + os.Getenv("PATH")
	env := []string{"PATH=" + pathEnv}
	return platform.RunAsCurrentUserWithEnv(ctx, env, npmPath, args)
}

func getVersion(ctx context.Context, path string) (string, error) {
	quietCtx := context.WithValue(ctx, "disable_logging", true)
	output, err := run(quietCtx, path, "--version")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(output), nil
}
