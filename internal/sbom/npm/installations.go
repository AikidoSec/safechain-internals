package npm

import (
	"os"
	"path/filepath"
	"runtime"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

func findBinaries() ([]string, error) {
	homeDir := platform.GetConfig().HomeDir
	binary := binaryName()

	candidates := knownPaths(binary)
	candidates = append(candidates, globPaths(homeDir, binary)...)

	seen := make(map[string]bool)
	var paths []string
	for _, candidate := range candidates {
		resolved, err := filepath.EvalSymlinks(candidate)
		if err != nil {
			resolved = candidate
		}
		if seen[resolved] {
			continue
		}
		if _, err := os.Stat(candidate); err != nil {
			continue
		}
		seen[resolved] = true
		paths = append(paths, candidate)
	}

	return paths, nil
}

func knownPaths(binary string) []string {
	paths := []string{
		"/usr/local/bin/" + binary,
		"/usr/bin/" + binary,
		"/opt/homebrew/bin/" + binary,
	}

	if runtime.GOOS == "windows" {
		appData := os.Getenv("APPDATA")
		programFiles := os.Getenv("ProgramFiles")
		if appData != "" {
			paths = append(paths, filepath.Join(appData, "npm", binary))
		}
		if programFiles != "" {
			paths = append(paths, filepath.Join(programFiles, "nodejs", binary))
		}
	}

	return paths
}

func globPaths(homeDir string, binary string) []string {
	patterns := []string{
		filepath.Join(homeDir, ".nvm", "versions", "node", "*", "bin", binary),
		filepath.Join(homeDir, ".fnm", "node-versions", "*", "installation", "bin", binary),
		filepath.Join(homeDir, ".volta", "tools", "image", "node", "*", "bin", binary),
		filepath.Join(homeDir, ".nodenv", "versions", "*", "bin", binary),
		filepath.Join(homeDir, ".asdf", "installs", "nodejs", "*", "bin", binary),
		"/usr/local/n/versions/node/*/bin/" + binary,
	}

	if runtime.GOOS == "windows" {
		appData := os.Getenv("APPDATA")
		if appData != "" {
			patterns = append(patterns,
				filepath.Join(appData, "nvm", "*", binary),
				filepath.Join(appData, "fnm", "node-versions", "*", "installation", binary),
			)
		}
	}

	var results []string
	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		results = append(results, matches...)
	}
	return results
}
