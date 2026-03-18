package cloud

import (
	"github.com/AikidoSec/safechain-internals/internal/device"
	"github.com/AikidoSec/safechain-internals/internal/sbom"
	"github.com/AikidoSec/safechain-internals/internal/version"
)

type HeartbeatEvent struct {
	DeviceInfo  device.DeviceInfo   `json:"device"`
	VersionInfo version.VersionInfo `json:"version"`
}

type SBOMEvent struct {
	DeviceInfo  device.DeviceInfo   `json:"device"`
	VersionInfo version.VersionInfo `json:"version"`
	SBOM        sbom.SBOM           `json:"sbom"`
}

// PackageInstallRequest represents a single package in an installation approval request.
type PackageInstallRequest struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// EcosystemPackages groups packages by ecosystem for an installation approval request.
type EcosystemPackages struct {
	Ecosystem string                  `json:"ecosystem"`
	Packages  []PackageInstallRequest `json:"packages"`
}

// RequestPackageInstallationEvent is the body sent to requestPackageInstallation.
type RequestPackageInstallationEvent struct {
	SBOM struct {
		Ecosystems []EcosystemPackages `json:"ecosystems"`
	} `json:"sbom"`
}
