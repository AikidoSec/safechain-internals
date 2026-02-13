package device

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"runtime"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

const (
	DeviceInfoVersion = 1
)

type DeviceInfo struct {
	Version         int    `json:"version"`
	DeviceID        string `json:"device_id"`
	Hostname        string `json:"hostname"`
	User            string `json:"user"`
	Group           string `json:"group"`
	OSType          string `json:"os_type"`
	OSVersion       string `json:"os_version"`
	CPUArchitecture string `json:"cpu_architecture"`
}

func NewDeviceInfo() *DeviceInfo {
	var err error

	d := &DeviceInfo{
		Version:         DeviceInfoVersion,
		OSType:          runtime.GOOS,
		CPUArchitecture: runtime.GOARCH,
	}

	d.User, _, d.Group, _, err = platform.GetCurrentUser(context.Background())
	if err != nil {
		log.Println("failed to get current user:", err)
		return nil
	}

	if hostname, err := os.Hostname(); err == nil {
		d.Hostname = hostname
	}

	d.OSVersion = platform.GetOSVersion()
	rawDeviceID, err := platform.GetDeviceID()
	if err != nil {
		log.Println("failed to get device ID:", err)
		return nil
	}
	hash := sha256.Sum256([]byte(rawDeviceID))
	d.DeviceID = hex.EncodeToString(hash[:])
	return d
}

func (d *DeviceInfo) String() string {
	b, _ := json.MarshalIndent(d, "", "  ")
	return string(b)
}
