package pip

import (
	"context"
	"fmt"
	"runtime"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

var defaultBinaryNames = []string{"pip3", "pip"}

func binaryNames() []string {
	if runtime.GOOS == "windows" {
		return []string{"pip3.exe", "pip.exe"}
	}
	return defaultBinaryNames
}

func runPip(ctx context.Context, pipPath string, args ...string) (string, error) {
	return platform.RunAsCurrentUserWithPathEnv(context.WithValue(ctx, "disable_logging", true), pipPath, args...)
}

func getVersion(ctx context.Context, path string) (string, error) {
	output, err := runPip(ctx, path, "--version")
	if err != nil {
		return "", err
	}
	return parsePipVersion(output)
}

// parsePipVersion extracts the pip version from pip --version output.
// Expected format: "pip X.Y.Z from /path/to/pip (python X.Y)"
func parsePipVersion(output string) (string, error) {
	trimmed := strings.TrimSpace(output)
	if !strings.HasPrefix(trimmed, "pip ") {
		return "", fmt.Errorf("unexpected pip version output: %s", trimmed)
	}
	fields := strings.Fields(trimmed)
	if len(fields) < 2 {
		return "", fmt.Errorf("unexpected pip version output: %s", trimmed)
	}
	return fields[1], nil
}
