package ingress

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	"github.com/AikidoSec/safechain-internals/internal/config"
	"github.com/AikidoSec/safechain-internals/internal/proxy"
)

type setupCheckResult struct {
	Steps []string `json:"steps"`
}

func ComputeSetupSteps(ctx context.Context, cfg *config.ConfigInfo) []string {
	var steps []string

	if cfg.Token == "" {
		steps = append(steps, "token")
	}

	if activated, err := IsNetworkExtensionActivated(ctx); err != nil || !activated {
		steps = append(steps, "activate-extension")
	}

	if allowed, err := IsNetworkExtensionVpnAllowed(ctx); err != nil || !allowed {
		steps = append(steps, "allow-vpn")
	}

	if !proxy.ProxyCAInstalled() {
		steps = append(steps, "start-proxy")
		steps = append(steps, "install-ca")
	} else if len(steps) > 0 {
		steps = append(steps, "start-proxy")
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
