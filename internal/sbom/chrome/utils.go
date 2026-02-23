package chrome

import (
	"context"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

func runBrowserVersion(ctx context.Context, binaryPath string) (string, error) {
	quietCtx := context.WithValue(ctx, "disable_logging", true)
	output, err := platform.RunAsCurrentUserWithPathEnv(quietCtx, binaryPath, "--version")
	if err != nil {
		return "", err
	}

	return parseVersionOutput(strings.TrimSpace(output)), nil
}

// parseVersionOutput extracts the version number from browser --version output.
// e.g. "Google Chrome 120.0.6099.109" -> "120.0.6099.109"
func parseVersionOutput(output string) string {
	lines := strings.SplitN(output, "\n", 2)
	if len(lines) == 0 {
		return ""
	}
	line := strings.TrimSpace(lines[0])

	for _, part := range strings.Fields(line) {
		if len(part) > 0 && part[0] >= '0' && part[0] <= '9' {
			return part
		}
	}

	return line
}
