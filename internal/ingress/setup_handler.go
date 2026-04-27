package ingress

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/AikidoSec/safechain-internals/internal/config"
	"github.com/AikidoSec/safechain-internals/internal/platform"
	"github.com/AikidoSec/safechain-internals/internal/proxy"
)

type setupCheckResult struct {
	Steps []string `json:"steps"`
}

func IsSetupOk(ctx context.Context, cfg *config.ConfigInfo) bool {
	return len(ComputeSetupSteps(ctx, cfg)) == 0
}

// IsRebootRequired reports whether the system needs to reboot to finish setup.
// The package installer creates an install marker file in the run directory;
// if that file's modification time is after the last system boot, the user
// has not rebooted since (re)installing.
func IsRebootRequired() bool {
	bootTime := platform.GetSystemBootTime()
	if bootTime.IsZero() {
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

func (s *Server) handleSetupCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.validateUIToken(w, r) {
		return
	}

	steps := ComputeSetupSteps(r.Context(), s.config)
	if len(steps) == 0 {
		w.WriteHeader(http.StatusOK)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusConflict)
	if err := json.NewEncoder(w).Encode(setupCheckResult{Steps: steps}); err != nil {
		log.Printf("ingress: setup check encode: %v", err)
	}
}

func (s *Server) handleSetupStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.validateUIToken(w, r) {
		return
	}

	steps := ComputeSetupSteps(r.Context(), s.config)
	s.ui.StartSetupWizard(steps)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(setupCheckResult{Steps: steps}); err != nil {
		log.Printf("ingress: setup start encode: %v", err)
	}
}
