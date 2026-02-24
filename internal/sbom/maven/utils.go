package maven

import (
	"context"
	"fmt"
	"runtime"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

const (
	unixBinaryName    = "mvn"
	windowsBinaryName = "mvn.cmd"
)

func binaryName() string {
	if runtime.GOOS == "windows" {
		return windowsBinaryName
	}
	return unixBinaryName
}

func runMvn(ctx context.Context, mvnPath string, args ...string) (string, error) {
	return platform.RunAsCurrentUserWithPathEnv(ctx, mvnPath, args...)
}

// getVersion runs `mvn --version` and parses the Maven version from the first line.
// Output format: "Apache Maven 3.9.6 (bc0240f3c...)"
func getVersion(ctx context.Context, path string) (string, error) {
	quietCtx := context.WithValue(ctx, "disable_logging", true)
	output, err := runMvn(quietCtx, path, "--version")
	if err != nil {
		return "", err
	}
	return parseMavenVersion(output)
}

func parseMavenVersion(output string) (string, error) {
	firstLine := strings.SplitN(strings.TrimSpace(output), "\n", 2)[0]
	// "Apache Maven 3.9.6 (bc0240f3c...)" -> extract version after "Apache Maven "
	const prefix = "Apache Maven "
	if !strings.HasPrefix(firstLine, prefix) {
		return "", fmt.Errorf("unexpected mvn version output: %s", firstLine)
	}
	rest := firstLine[len(prefix):]
	version, _, _ := strings.Cut(rest, " ")
	if version == "" {
		return "", fmt.Errorf("could not parse version from: %s", firstLine)
	}
	return version, nil
}
