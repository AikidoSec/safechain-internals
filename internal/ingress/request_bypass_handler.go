package ingress

import (
	"encoding/json"
	"log"
	"net/http"
)

func (s *Server) handleRequestBypass(w http.ResponseWriter, r *http.Request) {
	var event RequestBypassEvent
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	log.Printf("Received request-bypass event: key=%s", event.Key)

	w.WriteHeader(http.StatusOK)
}
