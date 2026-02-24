package npm

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/AikidoSec/safechain-internals/internal/sbom"
)

const name = "npm"

type npmListOutput struct {
	Dependencies map[string]npmDependency `json:"dependencies"`
}

type npmDependency struct {
	Version string `json:"version"`
}

type Npm struct{}

func New() sbom.PackageManager {
	return &Npm{}
}

func (n *Npm) Name() string {
	return name
}

func (n *Npm) Installations(ctx context.Context) ([]sbom.InstalledVersion, error) {
	return findInstallations(ctx)
}

func (n *Npm) SBOM(ctx context.Context, installation sbom.InstalledVersion) ([]sbom.Package, error) {
	output, err := runNpm(ctx, installation.Path, "list", "-g", "--json")
	if err != nil {
		return nil, fmt.Errorf("failed to list global packages: %w", err)
	}

	var parsed npmListOutput
	if err := json.Unmarshal([]byte(output), &parsed); err != nil {
		return nil, fmt.Errorf("failed to parse npm list output: %w", err)
	}

	packages := make([]sbom.Package, 0, len(parsed.Dependencies))
	for pkgName, dep := range parsed.Dependencies {
		packages = append(packages, sbom.Package{
			Name:    pkgName,
			Version: dep.Version,
		})
	}

	return packages, nil
}
