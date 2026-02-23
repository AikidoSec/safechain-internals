package cloud

import (
	"github.com/AikidoSec/safechain-internals/internal/device"
	"github.com/AikidoSec/safechain-internals/internal/version"
)

type HeartbeatEvent struct {
	DeviceInfo  *device.DeviceInfo   `json:"device_info"`
	VersionInfo *version.VersionInfo `json:"version_info"`
}

type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type SBOMEvent struct {
	DeviceInfo *device.DeviceInfo `json:"device_info"`
	Packages   []Package          `json:"packages"`
}
