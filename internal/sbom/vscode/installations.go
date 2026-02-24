package vscode

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"runtime"

	"github.com/AikidoSec/safechain-internals/internal/platform"
	"github.com/AikidoSec/safechain-internals/internal/sbom"
)

type variant struct {
	name   string
	extDir string
	bins   []string
}

var variants = []variant{
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

func findInstallations(ctx context.Context) ([]sbom.InstalledVersion, error) {
	homeDir := platform.GetConfig().HomeDir
	var installations []sbom.InstalledVersion

	for _, variant := range variants {
		extPath := filepath.Join(homeDir, variant.extDir)
		if _, err := os.Stat(extPath); err != nil {
			continue
		}

		binaryPath, version := getEditorBinaryAndVersion(ctx, variant, homeDir)
		if binaryPath == "" {
			continue
		}
		log.Printf("Found %s %s at: %s (extensions at: %s)", variant.name, version, binaryPath, extPath)
		installations = append(installations, sbom.InstalledVersion{
			Variant:  variant.name,
			Version:  version,
			Path:     binaryPath,
			DataPath: extPath,
		})
	}

	return installations, nil
}

func getEditorBinaryAndVersion(ctx context.Context, v variant, homeDir string) (binaryPath string, version string) {
	for _, bin := range v.bins {
		paths := findEditorBinary(bin, homeDir)
		for _, p := range paths {
			ver, err := runEditorVersion(ctx, p)
			if err != nil {
				continue
			}
			return p, ver
		}
	}
	return "", ""
}

func findEditorBinary(name string, homeDir string) []string {
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
		localAppData := filepath.Join(homeDir, "AppData", "Local")
		programFiles := os.Getenv("ProgramFiles")

		userPaths := map[string][]string{
			"code":          {filepath.Join(localAppData, "Programs", "Microsoft VS Code", "bin", cmdName)},
			"code-insiders": {filepath.Join(localAppData, "Programs", "Microsoft VS Code Insiders", "bin", cmdName)},
			"cursor":        {filepath.Join(localAppData, "Programs", "cursor", "resources", "app", "bin", cmdName)},
			"codium":        {filepath.Join(localAppData, "Programs", "VSCodium", "bin", cmdName)},
			"vscodium":      {filepath.Join(localAppData, "Programs", "VSCodium", "bin", "codium.cmd")},
		}
		if paths, ok := userPaths[name]; ok {
			candidates = append(candidates, paths...)
		}

		if programFiles != "" {
			systemPaths := map[string][]string{
				"code":          {filepath.Join(programFiles, "Microsoft VS Code", "bin", cmdName)},
				"code-insiders": {filepath.Join(programFiles, "Microsoft VS Code - Insiders", "bin", cmdName)},
				"codium":        {filepath.Join(programFiles, "VSCodium", "bin", cmdName)},
				"vscodium":      {filepath.Join(programFiles, "VSCodium", "bin", "codium.cmd")},
			}
			if paths, ok := systemPaths[name]; ok {
				candidates = append(candidates, paths...)
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
