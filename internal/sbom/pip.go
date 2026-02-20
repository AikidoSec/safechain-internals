package sbom

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

const pipName = "pip"

var pipBinaryNames = []string{"pip3", "pip"}

type pipListEntry struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Pip struct{}

func NewPipPackageManager() PackageManager {
	return &Pip{}
}

func (p *Pip) Name() string {
	return pipName
}

func (p *Pip) Installations(ctx context.Context) ([]InstalledVersion, error) {
	paths, err := findPipBinaries()
	if err != nil {
		return nil, fmt.Errorf("failed to find pip binaries: %w", err)
	}
	log.Printf("Found %d pip binaries: %v", len(paths), paths)

	var installations []InstalledVersion
	for _, path := range paths {
		version, err := getPipVersion(ctx, path)
		if err != nil {
			log.Printf("Skipping pip at %s: %v", path, err)
			continue
		}
		log.Printf("Found pip %s at: %s", version, path)
		installations = append(installations, InstalledVersion{
			Version: version,
			Path:    path,
		})
	}

	return installations, nil
}

func (p *Pip) SBOM(ctx context.Context, installation InstalledVersion) ([]Package, error) {
	output, err := runPip(ctx, installation.Path, "list", "--format=json")
	if err != nil {
		return nil, fmt.Errorf("failed to list packages: %w", err)
	}

	var parsed []pipListEntry
	if err := json.Unmarshal([]byte(output), &parsed); err != nil {
		return nil, fmt.Errorf("failed to parse pip list output: %w", err)
	}

	skipPackages := map[string]bool{
		"pip":        true,
		"setuptools": true,
		"wheel":      true,
	}

	packages := make([]Package, 0, len(parsed))
	for _, entry := range parsed {
		if skipPackages[strings.ToLower(entry.Name)] {
			continue
		}
		packages = append(packages, Package{
			Name:    entry.Name,
			Version: entry.Version,
		})
	}

	return packages, nil
}

func pipBinaries() []string {
	if runtime.GOOS == "windows" {
		return []string{"pip3.exe", "pip.exe"}
	}
	return pipBinaryNames
}

func findPipBinaries() ([]string, error) {
	homeDir := platform.GetConfig().HomeDir
	binaries := pipBinaries()

	var candidates []string
	for _, binary := range binaries {
		candidates = append(candidates, knownPipPaths(binary)...)
		candidates = append(candidates, globPipPaths(homeDir, binary)...)
	}
	candidates = append(candidates, globVersionedPipPaths(homeDir)...)

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

func knownPipPaths(binary string) []string {
	return []string{
		"/usr/local/bin/" + binary,
		"/usr/bin/" + binary,
		"/opt/homebrew/bin/" + binary,
	}
}

func globPipPaths(homeDir string, binary string) []string {
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

// globVersionedPipPaths finds versioned pip binaries like pip3.9, pip3.10, pip2.7.
func globVersionedPipPaths(homeDir string) []string {
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

func runPip(ctx context.Context, pipPath string, args ...string) (string, error) {
	binDir := filepath.Dir(pipPath)
	pathEnv := binDir

	resolved, err := filepath.EvalSymlinks(pipPath)
	if err == nil {
		resolvedDir := filepath.Dir(resolved)
		if resolvedDir != binDir {
			pathEnv = binDir + string(os.PathListSeparator) + resolvedDir
		}
	}

	pathEnv = pathEnv + string(os.PathListSeparator) + os.Getenv("PATH")
	env := []string{"PATH=" + pathEnv}
	return platform.RunAsCurrentUserWithEnv(ctx, env, pipPath, args)
}

func getPipVersion(ctx context.Context, path string) (string, error) {
	quietCtx := context.WithValue(ctx, "disable_logging", true)
	output, err := runPip(quietCtx, path, "--version")
	if err != nil {
		return "", err
	}
	// Output format: "pip X.Y.Z from /path/to/pip (python X.Y)"
	trimmed := strings.TrimSpace(output)
	start := strings.Index(trimmed, "(python ")
	end := strings.Index(trimmed, ")")
	if start == -1 || end == -1 || end <= start {
		return "", fmt.Errorf("unexpected pip version output: %s", trimmed)
	}
	return trimmed[start+len("(python ") : end], nil
}
