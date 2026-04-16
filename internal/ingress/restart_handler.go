package ingress

import (
	"encoding/json"
	"log"
	"net/http"
)

type restartResult struct {
	Status string `json:"status"`
}

func (s *Server) handleSetupRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.validateUIToken(w, r) {
		return
	}

	w.Header().Set("Content-Type", "application/json")

	if err := requestSystemRestart(r.Context()); err != nil {
		log.Printf("ingress: system restart: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(restartResult{Status: "restarting"}); err != nil {
		log.Printf("ingress: restart encode: %v", err)
	}
}
