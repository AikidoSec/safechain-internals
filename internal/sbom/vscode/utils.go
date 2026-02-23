package vscode

import (
	"context"
	"fmt"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

func runEditorVersion(ctx context.Context, binaryPath string) (string, error) {
	quietCtx := context.WithValue(ctx, "disable_logging", true)
	output, err := platform.RunAsCurrentUser(quietCtx, binaryPath, []string{"--version"})
	if err != nil {
		return "", err
	}

	// Extract only the version string from the first line, ignoring commit and architecture details
	lines := strings.SplitN(strings.TrimSpace(output), "\n", 2)
	if len(lines) == 0 || lines[0] == "" {
		return "", fmt.Errorf("empty version output")
	}
	return strings.TrimSpace(lines[0]), nil
}
