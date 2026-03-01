package npm

import (
	"context"
	"runtime"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/platform"
	"github.com/AikidoSec/safechain-internals/internal/sbom"
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
	return platform.RunAsCurrentUserWithPathEnv(context.WithValue(ctx, "disable_logging", true), npmPath, args...)
}

func getVersion(ctx context.Context, path string) (string, error) {
	quietCtx := context.WithValue(ctx, "disable_logging", true)
	output, err := runNpm(quietCtx, path, "--version")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(output), nil
}

// collectDependencies extracts all unique package versions from the dependency tree
// to build a complete SBOM inventory, avoiding duplicate entries for transitive dependencies.
func collectDependencies(deps map[string]npmDependency, seen map[string]bool) []sbom.Package {
	var packages []sbom.Package
	for name, dep := range deps {
		if dep.Version == "" {
			continue
		}

		key := name + "@" + dep.Version
		if seen[key] {
			continue
		}
		seen[key] = true

		packages = append(packages, sbom.Package{
			Id:      name,
			Version: dep.Version,
		})

		packages = append(packages, collectDependencies(dep.Dependencies, seen)...)
	}
	return packages
}
