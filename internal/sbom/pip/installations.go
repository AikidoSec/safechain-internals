package pip

import (
	"os"
	"path/filepath"
	"runtime"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

func findBinaries() ([]string, error) {
	homeDir := platform.GetConfig().HomeDir
	binaries := binaryNames()

	var candidates []string
	for _, binary := range binaries {
		candidates = append(candidates, knownPaths(binary)...)
		candidates = append(candidates, globPaths(homeDir, binary)...)
	}
	candidates = append(candidates, globVersionedPaths(homeDir)...)

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
	return []string{
		"/usr/local/bin/" + binary,
		"/usr/bin/" + binary,
		"/opt/homebrew/bin/" + binary,
	}
}

func globPaths(homeDir string, binary string) []string {
	patterns := []string{
		filepath.Join(homeDir, ".local", "bin", binary),
		filepath.Join(homeDir, ".pyenv", "versions", "*", "bin", binary),
		filepath.Join(homeDir, ".conda", "envs", "*", "bin", binary),
		filepath.Join(homeDir, "miniconda3", "bin", binary),
		filepath.Join(homeDir, "miniconda3", "envs", "*", "bin", binary),
		"/opt/homebrew/miniconda3/bin/" + binary,
		"/opt/homebrew/miniconda3/envs/*/bin/" + binary,
		"/usr/local/miniconda3/bin/" + binary,
		"/usr/local/miniconda3/envs/*/bin/" + binary,
		filepath.Join(homeDir, "anaconda3", "bin", binary),
		filepath.Join(homeDir, "anaconda3", "envs", "*", "bin", binary),
		"/opt/homebrew/anaconda3/bin/" + binary,
		"/opt/homebrew/anaconda3/envs/*/" + "bin/" + binary,
		"/usr/local/anaconda3/bin/" + binary,
		"/usr/local/anaconda3/envs/*/" + "bin/" + binary,
		filepath.Join(homeDir, ".asdf", "installs", "python", "*", "bin", binary),
	}

	if runtime.GOOS == "windows" {
		localAppData := os.Getenv("LOCALAPPDATA")
		programFiles := os.Getenv("ProgramFiles")
		if localAppData != "" {
			patterns = append(patterns,
				filepath.Join(localAppData, "Programs", "Python", "*", "Scripts", binary),
			)
		}
		if programFiles != "" {
			patterns = append(patterns,
				filepath.Join(programFiles, "Python", "*", "Scripts", binary),
			)
		}
		patterns = append(patterns,
			filepath.Join(homeDir, ".pyenv", "pyenv-win", "versions", "*", "Scripts", binary),
			filepath.Join(homeDir, "miniconda3", "Scripts", binary),
			filepath.Join(homeDir, "miniconda3", "envs", "*", "Scripts", binary),
			filepath.Join(homeDir, "anaconda3", "Scripts", binary),
			filepath.Join(homeDir, "anaconda3", "envs", "*", "Scripts", binary),
		)
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

// globVersionedPaths finds versioned pip binaries like pip3.9, pip3.10, pip2.7.
func globVersionedPaths(homeDir string) []string {
	pattern := "pip[23].[0-9]*"
	if runtime.GOOS == "windows" {
		pattern = "pip[23].[0-9]*.exe"
	}

	dirs := []string{
		"/usr/local/bin",
		"/usr/bin",
		"/opt/homebrew/bin",
		filepath.Join(homeDir, ".local", "bin"),
	}

	var results []string
	for _, dir := range dirs {
		matches, err := filepath.Glob(filepath.Join(dir, pattern))
		if err != nil {
			continue
		}
		results = append(results, matches...)
	}
	return results
}
