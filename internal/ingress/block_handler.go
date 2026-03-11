package ingress

import (
	"encoding/json"
	"net/http"
)

func (s *Server) handleBlock(w http.ResponseWriter, r *http.Request) {
	var event BlockEvent
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	blocked := s.eventStore.Add(event)
	go s.ui.NotifyBlocked(blocked)

	w.WriteHeader(http.StatusOK)
}
