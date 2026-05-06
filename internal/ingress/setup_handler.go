package ingress

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	"github.com/AikidoSec/safechain-internals/internal/config"
)

type setupCheckResult struct {
	Steps []string `json:"steps"`
}

func IsSetupOk(ctx context.Context, cfg *config.ConfigInfo) bool {
	return len(ComputeSetupSteps(ctx, cfg)) == 0
}

// IsRebootRequired and ComputeSetupSteps are implemented per-platform:
//   - setup_handler_darwin.go for macOS (Network Extension install / allow-VPN flow).
//   - setup_handler_windows.go for Windows (kernel L4 driver via MSI / pnputil).

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
