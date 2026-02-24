package maven

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
		programFiles := os.Getenv("ProgramFiles")
		if programFiles != "" {
			paths = append(paths, filepath.Join(programFiles, "apache-maven", "bin", binary))
		}
	}

	return paths
}

func globPaths(homeDir string, binary string) []string {
	patterns := []string{
		filepath.Join(homeDir, ".sdkman", "candidates", "maven", "*", "bin", binary),
		filepath.Join(homeDir, ".asdf", "installs", "maven", "*", "bin", binary),
		filepath.Join(homeDir, ".mise", "installs", "maven", "*", "bin", binary),
		"/opt/maven/bin/" + binary,
		"/opt/apache-maven-*/bin/" + binary,
		"/usr/local/apache-maven-*/bin/" + binary,
		"/usr/share/maven/bin/" + binary,
	}

	if runtime.GOOS == "windows" {
		programFiles := os.Getenv("ProgramFiles")
		if programFiles != "" {
			patterns = append(patterns,
				filepath.Join(programFiles, "apache-maven-*", "bin", binary),
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
