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
