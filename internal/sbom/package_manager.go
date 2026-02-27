package sbom

import (
	"context"
)

type InstalledVersion struct {
	Variant  string
	Version  string
	Path     string
	DataPath string
}

type Package struct {
	Id      string `json:"id"`
	Name    string `json:"name,omitempty"`
	Version string `json:"version"`
}

// PackageManager represents a package ecosystem (e.g. "npm", "pip").
// A single PackageManager can have multiple Installations on the system
// (e.g. npm via nvm v18 at ~/.nvm/versions/node/v18/bin/npm and npm via
// nvm v20 at ~/.nvm/versions/node/v20/bin/npm, or vscode at
// /Applications/Visual Studio Code.app and cursor at
// /Applications/Cursor.app), each producing its own SBOM.
type PackageManager interface {
	Name() string
	Installations(ctx context.Context) ([]InstalledVersion, error)
	SBOM(ctx context.Context, installation InstalledVersion) ([]Package, error)
}
