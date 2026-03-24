package skills

import (
	"context"
	"path/filepath"
	"runtime"

	"github.com/AikidoSec/safechain-internals/internal/platform"
	"github.com/AikidoSec/safechain-internals/internal/sbom"
)

func binaryName() string {
	if runtime.GOOS == "windows" {
		return "skills.cmd"
	}
	return "skills"
}

func npmBinaryName() string {
	if runtime.GOOS == "windows" {
		return "npm.cmd"
	}
	return "npm"
}

func npxBinaryName() string {
	if runtime.GOOS == "windows" {
		return "npx.cmd"
	}
	return "npx"
}

func runSkills(ctx context.Context, binaryPath string, args ...string) (string, error) {
	return platform.RunAsCurrentUserWithPathEnv(ctx, binaryPath, args...)
}

// findBinaries locates skills binaries by looking alongside npm installations,
// since skills is an npm global package and shares the same bin directory as npm.
// If skills is not installed as a standalone binary, npx is used as a fallback.
func findBinaries(homeDir string) []string {
	npmPaths := sbom.FindNodeBinaries(homeDir, npmBinaryName())
	binary := binaryName()

	var candidates []string
	for _, npmPath := range npmPaths {
		dir := filepath.Dir(npmPath)
		candidates = append(candidates, filepath.Join(dir, binary))
	}

	found := sbom.DeduplicatePaths(candidates)
	if len(found) > 0 {
		return found
	}

	// skills not installed globally: fall back to npx alongside any npm installation.
	npxBinary := npxBinaryName()
	for _, npmPath := range npmPaths {
		dir := filepath.Dir(npmPath)
		candidates = append(candidates, filepath.Join(dir, npxBinary))
	}
	return sbom.DeduplicatePaths(candidates)
}
