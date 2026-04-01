package ingress

import (
	"encoding/json"
	"log"
	"net/http"
)

func (s *Server) handlePermissionsUpdated(w http.ResponseWriter, r *http.Request) {
	var raw json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	log.Println("Got permissions update from proxy")
	go s.ui.NotifyPermissionsUpdated(raw)

	w.WriteHeader(http.StatusOK)
}
