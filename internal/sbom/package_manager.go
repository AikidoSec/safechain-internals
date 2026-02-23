package sbom

import (
	"context"
)

type InstalledVersion struct {
	Ecosystem string
	Version   string
	Path      string
	DataPath  string
}

type Package struct {
	ID      string `json:"id,omitempty"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type EcosystemEntry struct {
	Ecosystem string    `json:"ecosystem"`
	Version   string    `json:"version"`
	Path      string    `json:"path"`
	Packages  []Package `json:"packages"`
}

type SBOM struct {
	Entries []EcosystemEntry `json:"sbom"`
}

type PackageManager interface {
	Name() string
	Installations(ctx context.Context) ([]InstalledVersion, error)
	SBOM(ctx context.Context, installation InstalledVersion) ([]Package, error)
}
