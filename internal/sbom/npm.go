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
	"github.com/AikidoSec/safechain-internals/internal/utils"
)

const (
	name              = "npm"
	unixBinaryName    = "npm"
	windowsBinaryName = "npm.cmd"
)

type npmListOutput struct {
	Dependencies map[string]npmDependency `json:"dependencies"`
}

type npmDependency struct {
	Version string `json:"version"`
}

type Npm struct{}

func NewNpmPackageManager() PackageManager {
	return &Npm{}
}

func (n *Npm) Name() string {
	return name
}

func (n *Npm) Installations(ctx context.Context) ([]InstalledVersion, error) {
	paths, err := findNpmBinaries()
	if err != nil {
		return nil, fmt.Errorf("failed to find npm binaries: %w", err)
	}
	log.Printf("Found %d npm binaries: %v", len(paths), paths)

	var installations []InstalledVersion
	for _, path := range paths {
		version, err := getNpmVersion(ctx, path)
		if err != nil {
			log.Printf("Skipping npm at %s: %v", path, err)
			continue
		}
		log.Printf("Found npm %s at %s", version, path)
		installations = append(installations, InstalledVersion{
			Version: version,
			Path:    path,
		})
	}

	return installations, nil
}

func (n *Npm) SBOM(ctx context.Context, installation InstalledVersion) ([]Package, error) {
	output, err := runNpm(ctx, installation.Path, "list", "-g", "--json")
	if err != nil {
		return nil, fmt.Errorf("failed to list global packages: %w", err)
	}

	var parsed npmListOutput
	if err := json.Unmarshal([]byte(output), &parsed); err != nil {
		return nil, fmt.Errorf("failed to parse npm list output: %w", err)
	}

	packages := make([]Package, 0, len(parsed.Dependencies))
	for pkgName, dep := range parsed.Dependencies {
		if pkgName == name {
			continue
		}
		packages = append(packages, Package{
			Name:    pkgName,
			Version: dep.Version,
		})
	}

	return packages, nil
}

func npmBinaryName() string {
	if runtime.GOOS == "windows" {
		return windowsBinaryName
	}
	return unixBinaryName
}

func findNpmBinaries() ([]string, error) {
	homeDir := platform.GetConfig().HomeDir
	binary := npmBinaryName()

	candidates := knownNpmPaths(binary)
	candidates = append(candidates, globNpmPaths(homeDir, binary)...)

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

func knownNpmPaths(binary string) []string {
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

func globNpmPaths(homeDir string, binary string) []string {
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

func runNpm(ctx context.Context, npmPath string, args ...string) (string, error) {
	binDir := filepath.Dir(npmPath)
	pathEnv := binDir

	resolved, err := filepath.EvalSymlinks(npmPath)
	if err == nil {
		resolvedDir := filepath.Dir(resolved)
		if resolvedDir != binDir {
			pathEnv = binDir + string(os.PathListSeparator) + resolvedDir
		}
	}

	pathEnv = pathEnv + string(os.PathListSeparator) + os.Getenv("PATH")
	env := []string{"PATH=" + pathEnv}
	return utils.RunCommandWithEnv(ctx, env, npmPath, args...)
}

func getNpmVersion(ctx context.Context, path string) (string, error) {
	quietCtx := context.WithValue(ctx, "disable_logging", true)
	output, err := runNpm(quietCtx, path, "--version")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(output), nil
}
