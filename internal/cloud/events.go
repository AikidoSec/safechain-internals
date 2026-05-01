package cloud

import (
	"github.com/AikidoSec/safechain-internals/internal/device"
	"github.com/AikidoSec/safechain-internals/internal/sbom"
	"github.com/AikidoSec/safechain-internals/internal/version"
)

type Status struct {
	Protected         bool     `json:"protected"`
	MissingSetupSteps []string `json:"missing_setup_steps"`
}

type HeartbeatEvent struct {
	DeviceInfo  device.DeviceInfo   `json:"device"`
	VersionInfo version.VersionInfo `json:"version"`
	Status      Status              `json:"status"`
}

type HeartbeatResponse struct {
	CollectLogsRequestedAt *int64  `json:"collect_logs_requested_at,omitempty"`
	UpdateEnabled          *bool   `json:"update_enabled,omitempty"`
	UpdateVersion          *string `json:"update_version,omitempty"`
}

type SBOMEvent struct {
	DeviceInfo  device.DeviceInfo   `json:"device"`
	VersionInfo version.VersionInfo `json:"version"`
	SBOM        sbom.SBOM           `json:"sbom"`
}

type ActivityEvent struct {
	Action      string              `json:"action"`
	BlockReason string              `json:"block_reason,omitempty"`
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

type SubmittedEvent struct {
	ID             int    `json:"id"`
	Action         string `json:"action"`
	BlockReason    string `json:"block_reason"`
	Ecosystem      string `json:"ecosystem"`
	PackageID      string `json:"package_id"`
	PackageName    string `json:"package_name"`
	PackageVersion string `json:"package_version"`
	Timestamp      int64  `json:"timestamp"`
	Status         string `json:"status"`
}

type FetchSubmittedEventsResponse struct {
	Events []SubmittedEvent `json:"events"`
}

// RequestPackageInstallationEvent is the body sent to requestPackageInstallation.
type RequestPackageInstallationEvent struct {
	SBOM struct {
		Ecosystems []EcosystemPackages `json:"ecosystems"`
	} `json:"sbom"`
}
