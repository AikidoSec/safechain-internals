package npm

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/AikidoSec/safechain-internals/internal/sbom"
)

const name = "npm"

type npmDependency struct {
	Version      string                   `json:"version"`
	Dependencies map[string]npmDependency `json:"dependencies"`
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
	// --all includes the full dependency tree (not just top-level) so the SBOM is complete.
	output, err := runNpm(ctx, installation.Path, "list", "-g", "--all", "--json")
	if err != nil {
		return nil, fmt.Errorf("failed to list global packages: %w", err)
	}

	var root npmDependency
	if err := json.Unmarshal([]byte(output), &root); err != nil {
		return nil, fmt.Errorf("failed to parse npm list output: %w", err)
	}

	return collectDependencies(root.Dependencies, make(map[string]bool)), nil
}
