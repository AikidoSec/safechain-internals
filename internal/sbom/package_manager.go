package sbom

import (
	"context"
)

type InstalledVersion struct {
	Version string
	Path    string
}

type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type PackageManager interface {
	Name() string
	Installations(ctx context.Context) ([]InstalledVersion, error)
	SBOM(ctx context.Context, installation InstalledVersion) ([]Package, error)
}
