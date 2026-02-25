package chrome

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/sbom"
)

type ChromeExtensions struct{}

func New() sbom.PackageManager {
	return &ChromeExtensions{}
}

func (c *ChromeExtensions) Name() string {
	return "chrome-extensions"
}

func (c *ChromeExtensions) Installations(ctx context.Context) ([]sbom.InstalledVersion, error) {
	return findInstallations(ctx)
}

// SBOM scans all profiles within the browser data directory (DataPath)
// and deduplicates extensions across profiles.
func (c *ChromeExtensions) SBOM(_ context.Context, installation sbom.InstalledVersion) ([]sbom.Package, error) {
	profiles := findProfilesWithExtensions(installation.DataPath)

	packageMap := make(map[string]sbom.Package)

	for _, profile := range profiles {
		extDir := filepath.Join(installation.DataPath, profile, "Extensions")
		entries, err := os.ReadDir(extDir)
		if err != nil {
			log.Printf("Failed to read extensions directory for profile %s: %v", profile, err)
			continue
		}

		for _, entry := range entries {
			if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
				continue
			}

			extensionID := entry.Name()
			extPath := filepath.Join(extDir, extensionID)

			pkg, err := readLatestExtension(extPath, extensionID)
			if err != nil {
				log.Printf("Skipping Chrome extension %s: %v", extensionID, err)
				continue
			}

			if existing, ok := packageMap[extensionID]; !ok || pkg.Version > existing.Version {
				packageMap[extensionID] = *pkg
			}
		}
	}

	packages := make([]sbom.Package, 0, len(packageMap))
	for _, pkg := range packageMap {
		packages = append(packages, pkg)
	}

	return packages, nil
}
