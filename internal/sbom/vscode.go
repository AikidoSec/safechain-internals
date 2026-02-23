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

type vscodeVariant struct {
	name   string
	extDir string
	bins   []string
}

var vscodeVariants = []vscodeVariant{
	{
		name:   "code",
		extDir: filepath.Join(".vscode", "extensions"),
		bins:   []string{"code"},
	},
	{
		name:   "code-insiders",
		extDir: filepath.Join(".vscode-insiders", "extensions"),
		bins:   []string{"code-insiders"},
	},
	{
		name:   "cursor",
		extDir: filepath.Join(".cursor", "extensions"),
		bins:   []string{"cursor"},
	},
	{
		name:   "vscodium",
		extDir: filepath.Join(".vscode-oss", "extensions"),
		bins:   []string{"codium", "vscodium"},
	},
}

type vscodeExtensionManifest struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Publisher string `json:"publisher"`
}

type VSCodeExtensions struct{}

func NewVSCodeExtensionsManager() PackageManager {
	return &VSCodeExtensions{}
}

func (v *VSCodeExtensions) Name() string {
	return "vscode-extensions"
}

func (v *VSCodeExtensions) Installations(ctx context.Context) ([]InstalledVersion, error) {
	homeDir := platform.GetConfig().HomeDir
	var installations []InstalledVersion

	for _, variant := range vscodeVariants {
		extPath := filepath.Join(homeDir, variant.extDir)
		if _, err := os.Stat(extPath); err != nil {
			continue
		}

		binaryPath, version := getEditorBinaryAndVersion(ctx, variant)
		log.Printf("Found %s extensions at: %s (binary: %s, version: %s)", variant.name, extPath, binaryPath, version)
		installations = append(installations, InstalledVersion{
			Ecosystem: variant.name,
			Version:   version,
			Path:      binaryPath,
			DataPath:  extPath,
		})
	}

	return installations, nil
}

func (v *VSCodeExtensions) SBOM(_ context.Context, installation InstalledVersion) ([]Package, error) {
	entries, err := os.ReadDir(installation.DataPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read extensions directory: %w", err)
	}

	var packages []Package
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}

		pkg, err := readExtensionManifest(filepath.Join(installation.DataPath, entry.Name()))
		if err != nil {
			log.Printf("Skipping extension %s: %v", entry.Name(), err)
			continue
		}
		packages = append(packages, *pkg)
	}

	return packages, nil
}

func readExtensionManifest(extDir string) (*Package, error) {
	data, err := os.ReadFile(filepath.Join(extDir, "package.json"))
	if err != nil {
		return nil, fmt.Errorf("failed to read package.json: %w", err)
	}

	var manifest vscodeExtensionManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("failed to parse package.json: %w", err)
	}

	if manifest.Name == "" || manifest.Version == "" {
		return nil, fmt.Errorf("missing name or version in package.json")
	}

	name := manifest.Name
	if manifest.Publisher != "" {
		name = manifest.Publisher + "." + name
	}

	return &Package{
		Name:    name,
		Version: manifest.Version,
	}, nil
}

func getEditorBinaryAndVersion(ctx context.Context, variant vscodeVariant) (binaryPath string, version string) {
	for _, bin := range variant.bins {
		paths := findEditorBinary(bin)
		for _, p := range paths {
			v, err := runEditorVersion(ctx, p)
			if err != nil {
				continue
			}
			return p, v
		}
	}
	return "", ""
}

func findEditorBinary(name string) []string {
	var candidates []string

	if runtime.GOOS == "darwin" {
		appPaths := map[string]string{
			"code":          "/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code",
			"code-insiders": "/Applications/Visual Studio Code - Insiders.app/Contents/Resources/app/bin/code-insiders",
			"cursor":        "/Applications/Cursor.app/Contents/Resources/app/bin/cursor",
			"codium":        "/Applications/VSCodium.app/Contents/Resources/app/bin/codium",
			"vscodium":      "/Applications/VSCodium.app/Contents/Resources/app/bin/codium",
		}
		if p, ok := appPaths[name]; ok {
			candidates = append(candidates, p)
		}
	}

	if runtime.GOOS == "windows" {
		cmdName := name + ".cmd"
		localAppData := os.Getenv("LOCALAPPDATA")
		if localAppData != "" {
			candidates = append(candidates,
				filepath.Join(localAppData, "Programs", "Microsoft VS Code", "bin", cmdName),
				filepath.Join(localAppData, "Programs", "Microsoft VS Code Insiders", "bin", cmdName),
			)
			if name == "cursor" {
				candidates = append(candidates,
					filepath.Join(localAppData, "Programs", "cursor", "resources", "app", "bin", cmdName),
				)
			}
		}
	}

	candidates = append(candidates,
		"/usr/local/bin/"+name,
		"/usr/bin/"+name,
		"/snap/bin/"+name,
	)

	var found []string
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			found = append(found, c)
			break
		}
	}
	return found
}

func runEditorVersion(ctx context.Context, binaryPath string) (string, error) {
	quietCtx := context.WithValue(ctx, "disable_logging", true)
	output, err := platform.RunAsCurrentUser(quietCtx, binaryPath, []string{"--version"})
	if err != nil {
		return "", err
	}

	// `code --version` outputs: version\ncommit\narch
	lines := strings.SplitN(strings.TrimSpace(output), "\n", 2)
	if len(lines) == 0 || lines[0] == "" {
		return "", fmt.Errorf("empty version output")
	}
	return strings.TrimSpace(lines[0]), nil
}
