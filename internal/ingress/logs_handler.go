package ingress

import (
	"log"
	"net/http"

	"github.com/AikidoSec/safechain-internals/internal/logcollector"
)

func (s *Server) handleCollectLogs(w http.ResponseWriter, r *http.Request) {
	if !s.validateUIToken(w, r) {
		return
	}

	if err := logcollector.Collect(r.Context(), s.config); err != nil {
		log.Printf("ingress: log collection failed: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}
