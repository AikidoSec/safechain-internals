package pip

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"

	"github.com/AikidoSec/safechain-internals/internal/platform"
	"github.com/AikidoSec/safechain-internals/internal/sbom"
)

func findInstallations(ctx context.Context) ([]sbom.InstalledVersion, error) {
	paths, err := findBinaries()
	if err != nil {
		return nil, fmt.Errorf("failed to find pip binaries: %w", err)
	}

	var installations []sbom.InstalledVersion
	for _, path := range paths {
		version, err := getVersion(ctx, path)
		if err != nil {
			log.Printf("Skipping pip at %s: %v", path, err)
			continue
		}
		log.Printf("Found pip %s at: %s", version, path)
		installations = append(installations, sbom.InstalledVersion{
			Version: version,
			Path:    path,
		})
	}

	return installations, nil
}

func findBinaries() ([]string, error) {
	homeDir := platform.GetConfig().HomeDir
	binaries := binaryNames()

	var candidates []string
	for _, binary := range binaries {
		candidates = append(candidates, knownPaths(binary)...)
		candidates = append(candidates, globPaths(homeDir, binary)...)
	}
	candidates = append(candidates, globVersionedPaths(homeDir)...)

	return sbom.DeduplicatePaths(candidates), nil
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
		localAppData := filepath.Join(homeDir, "AppData", "Local")
		programFiles := os.Getenv("ProgramFiles")
		patterns = append(patterns,
			filepath.Join(localAppData, "Programs", "Python", "*", "Scripts", binary),
		)
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
		pattern += ".exe"
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
