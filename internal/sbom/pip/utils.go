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
	// Output format: "pip X.Y.Z from /path/to/pip (python X.Y)"
	trimmed := strings.TrimSpace(output)
	start := strings.Index(trimmed, "(python ")
	end := strings.Index(trimmed, ")")
	if start == -1 || end == -1 || end <= start {
		return "", fmt.Errorf("unexpected pip version output: %s", trimmed)
	}
	return trimmed[start+len("(python ") : end], nil
}
