package pip

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/AikidoSec/safechain-internals/internal/sbom"
)

const name = "pip"

type pipListEntry struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Pip struct{}

func New() sbom.PackageManager {
	return &Pip{}
}

func (p *Pip) Name() string {
	return name
}

func (p *Pip) Installations(ctx context.Context) ([]sbom.InstalledVersion, error) {
	paths, err := findBinaries()
	if err != nil {
		return nil, fmt.Errorf("failed to find pip binaries: %w", err)
	}
	log.Printf("Found %d pip binaries: %v", len(paths), paths)

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

func (p *Pip) SBOM(ctx context.Context, installation sbom.InstalledVersion) ([]sbom.Package, error) {
	output, err := run(ctx, installation.Path, "list", "--format=json")
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

	packages := make([]sbom.Package, 0, len(parsed))
	for _, entry := range parsed {
		if skipPackages[strings.ToLower(entry.Name)] {
			continue
		}
		packages = append(packages, sbom.Package{
			Name:    entry.Name,
			Version: entry.Version,
		})
	}

	return packages, nil
}
