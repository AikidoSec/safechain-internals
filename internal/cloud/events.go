package cloud

import (
	"github.com/AikidoSec/safechain-internals/internal/device"
	"github.com/AikidoSec/safechain-internals/internal/sbom"
	"github.com/AikidoSec/safechain-internals/internal/version"
)

type HeartbeatEvent struct {
	DeviceInfo  device.DeviceInfo   `json:"device_info"`
	VersionInfo version.VersionInfo `json:"version_info"`
}

type SBOMEvent struct {
	DeviceInfo device.DeviceInfo `json:"device_info"`
	SBOM       sbom.SBOM         `json:"sbom"`
}
