//go:build darwin

package ingress

import (
	"context"
	"os"

	"github.com/AikidoSec/safechain-internals/internal/config"
	"github.com/AikidoSec/safechain-internals/internal/platform"
	"github.com/AikidoSec/safechain-internals/internal/proxy"
)

// IsRebootRequired reports whether the system needs to reboot to finish setup.
// The package installer creates an install marker file in the run directory;
// if that file's modification time is after the last system boot, the user
// has not rebooted since (re)installing.
//
// During an upgrade the preinstall script drops an upgrade marker so we can
// skip the reboot prompt — upgrades reuse the existing kernel/extension state
// and don't require the user to reboot.
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

func ComputeSetupSteps(ctx context.Context, cfg *config.ConfigInfo) []string {
	var steps []string

	if cfg.Token == "" {
		steps = append(steps, "token")
	}

	if installed, err := IsNetworkExtensionInstalled(ctx); err != nil || !installed {
		steps = append(steps, "install-extension")
		steps = append(steps, "enable-extension")
		steps = append(steps, "allow-vpn")
	} else if activated, err := IsNetworkExtensionActivated(ctx); err != nil || !activated {
		steps = append(steps, "enable-extension")
		steps = append(steps, "allow-vpn")
	} else {
		if allowed, err := IsNetworkExtensionVpnAllowed(ctx); err != nil || !allowed {
			steps = append(steps, "allow-vpn")
		}
	}

	if !proxy.ProxyCAInstalled() {
		// The setup wizard needs to start the proxy in order to access the CA certificate
		// and be able to install it in the next step
		steps = append(steps, "start-proxy")
		steps = append(steps, "install-ca")
	}

	if IsRebootRequired() {
		steps = append(steps, "reboot")
	}

	return steps
}
