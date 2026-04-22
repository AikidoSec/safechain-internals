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
// and reports every installed version of each extension, deduplicating
// identical (id, version) pairs that appear across multiple profiles.
//
// Each package carries a State of "enabled" or "disabled" reflecting the
// per-profile Preferences / Secure Preferences metadata. An extension enabled
// in any profile where it is installed is reported as enabled. Missing state
// entries still fail open to enabled so that extensions on disk but unknown to
// Chrome's metadata continue to surface in the SBOM.
func (c *ChromeExtensions) SBOM(_ context.Context, installation sbom.InstalledVersion) ([]sbom.Package, error) {
	profiles := findProfilesWithExtensions(installation.DataPath)

	seen := make(map[string]bool)
	enabledSomewhere := make(map[string]bool)
	var packages []sbom.Package

	for _, profile := range profiles {
		profileDir := filepath.Join(installation.DataPath, profile)
		extDir := filepath.Join(profileDir, "Extensions")
		entries, err := os.ReadDir(extDir)
		if err != nil {
			log.Printf("Failed to read extensions directory for profile %s: %v", profile, err)
			continue
		}

		states := readProfileExtensionStates(profileDir)

		for _, entry := range entries {
			if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
				continue
			}

			extensionID := entry.Name()
			extPath := filepath.Join(extDir, extensionID)

			enabled, known := states[extensionID]
			if !known || enabled {
				enabledSomewhere[extensionID] = true
			}

			for _, pkg := range readExtensionVersions(extPath, extensionID) {
				key := pkg.Id + "@" + pkg.Version
				if seen[key] {
					continue
				}
				seen[key] = true
				packages = append(packages, pkg)
			}
		}
	}

	for i := range packages {
		if enabledSomewhere[packages[i].Id] {
			packages[i].State = "enabled"
		} else {
			packages[i].State = "disabled"
		}
	}

	return packages, nil
}
