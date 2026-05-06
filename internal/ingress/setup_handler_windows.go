//go:build windows

package ingress

import (
	"context"
	"os"

	"github.com/AikidoSec/safechain-internals/internal/config"
	"github.com/AikidoSec/safechain-internals/internal/platform"
	"github.com/AikidoSec/safechain-internals/internal/proxy"
)

// IsRebootRequired reports whether the system needs to reboot to finish setup.
// On Windows the kernel-mode L4 WFP driver may need a reboot to fully load
// after the MSI's pnputil custom action stages it (pnputil exit code 3010
// means "reboot required"). The MSI install custom action drops .installed_at
// in the run directory; if that file's modification time is after the last
// system boot, the user has not rebooted since (re)installing.
//
// During a major upgrade an .upgraded marker is written so we can skip the
// reboot prompt — upgrades reuse the existing kernel driver state.
func IsRebootRequired() bool {
	if _, err := os.Stat(platform.GetUpgradeMarkerPath()); err == nil {
		return false
	}
	bootTime, err := platform.GetSystemBootTime()
	if err != nil || bootTime.IsZero() {
		return false
	}
	info, err := os.Stat(platform.GetInstallMarkerPath())
	if err != nil {
		return false
	}
	return info.ModTime().After(bootTime)
}

// ComputeSetupSteps returns the setup-wizard steps still pending on Windows.
// Unlike macOS, Windows has no Network-Extension install/allow-VPN flow:
// the kernel L4 driver is installed by the MSI and loaded on demand when
// the user-mode SafeChainL4Proxy.exe opens \\.\SafechainL4Proxy. So the
// only steps the wizard ever needs are: token, start-proxy, install-ca,
// and (conditionally) reboot.
func ComputeSetupSteps(_ context.Context, cfg *config.ConfigInfo) []string {
	var steps []string

	if cfg.Token == "" {
		steps = append(steps, "token")
	}

	if !proxy.ProxyCAInstalled() {
		// The setup wizard needs to start the proxy in order to access the
		// CA certificate and install it in the next step.
		steps = append(steps, "start-proxy")
		steps = append(steps, "install-ca")
	}

	if IsRebootRequired() {
		steps = append(steps, "reboot")
	}

	return steps
}
