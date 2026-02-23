package vscode

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/sbom"
)

type extensionManifest struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Publisher string `json:"publisher"`
}

type VSCodeExtensions struct{}

func New() sbom.PackageManager {
	return &VSCodeExtensions{}
}

func (v *VSCodeExtensions) Name() string {
	return "vscode-extensions"
}

func (v *VSCodeExtensions) Installations(ctx context.Context) ([]sbom.InstalledVersion, error) {
	return findInstallations(ctx)
}

func (v *VSCodeExtensions) SBOM(_ context.Context, installation sbom.InstalledVersion) ([]sbom.Package, error) {
	entries, err := os.ReadDir(installation.DataPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read extensions directory: %w", err)
	}

	var packages []sbom.Package
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

func readExtensionManifest(extDir string) (*sbom.Package, error) {
	data, err := os.ReadFile(filepath.Join(extDir, "package.json"))
	if err != nil {
		return nil, fmt.Errorf("failed to read package.json: %w", err)
	}

	var manifest extensionManifest
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

	return &sbom.Package{
		Name:    name,
		Version: manifest.Version,
	}, nil
}
