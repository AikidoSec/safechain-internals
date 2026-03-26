package sbom

import (
	"os"
	"path/filepath"
	"runtime"
)

// FindNodeBinaries returns paths to a Node.js ecosystem binary (e.g. "npm", "skills")
// across all known installation locations: system paths, homebrew, and version managers.
func FindNodeBinaries(homeDir, binary string) []string {
	candidates := nodeKnownPaths(binary)
	candidates = append(candidates, nodeGlobPaths(homeDir, binary)...)
	return DeduplicatePaths(candidates)
}

func nodeKnownPaths(binary string) []string {
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

func nodeGlobPaths(homeDir, binary string) []string {
	patterns := []string{
		filepath.Join(homeDir, ".nvm", "versions", "node", "*", "bin", binary),
		filepath.Join(homeDir, ".fnm", "node-versions", "*", "installation", "bin", binary),
		filepath.Join(homeDir, ".volta", "tools", "image", "node", "*", "bin", binary),
		filepath.Join(homeDir, ".nodenv", "versions", "*", "bin", binary),
		filepath.Join(homeDir, ".asdf", "installs", "nodejs", "*", "bin", binary),
		"/usr/local/n/versions/node/*/bin/" + binary,
	}
	if runtime.GOOS == "windows" {
		if appData := os.Getenv("APPDATA"); appData != "" {
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
			// filepath.Glob only errors on malformed patterns
			// skipping preserves best-effort discovery if one ever becomes invalid.
			continue
		}
		results = append(results, matches...)
	}
	return results
}
