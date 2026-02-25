package pip

import (
	"context"
	"encoding/json"
	"fmt"

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
	return findInstallations(ctx)
}

func (p *Pip) SBOM(ctx context.Context, installation sbom.InstalledVersion) ([]sbom.Package, error) {
	output, err := runPip(ctx, installation.Path, "list", "--format=json")
	if err != nil {
		return nil, fmt.Errorf("failed to list packages: %w", err)
	}

	var parsed []pipListEntry
	if err := json.Unmarshal([]byte(output), &parsed); err != nil {
		return nil, fmt.Errorf("failed to parse pip list output: %w", err)
	}

	packages := make([]sbom.Package, 0, len(parsed))
	for _, entry := range parsed {
		packages = append(packages, sbom.Package{
			Id:      entry.Name,
			Name:    entry.Name,
			Version: entry.Version,
		})
	}

	return packages, nil
}
