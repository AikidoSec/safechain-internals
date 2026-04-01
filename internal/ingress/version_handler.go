package ingress

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/AikidoSec/safechain-internals/internal/version"
)

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	if !s.validateUIToken(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	resp := map[string]string{"version": version.Version}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("ingress: failed to write version response: %v", err)
	}
}
