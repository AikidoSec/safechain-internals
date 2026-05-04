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

// AiUsageModel is one observed (provider, model) pair with its most recent
// observation timestamp on this device. `last_seen_at` is Unix seconds —
// matches the `as_endpoint_protection_ai_models.last_seen_at` column type.
// When omitted, the cloud falls back to stamping receive-time.
type AiUsageModel struct {
	Provider   string `json:"provider"`
	Model      string `json:"model"`
	LastSeenAt int64  `json:"last_seen_at,omitempty"`
}

// AiUsageStatsEvent is the body sent to reportAiStats.
type AiUsageStatsEvent struct {
	Models []AiUsageModel `json:"models"`
}
