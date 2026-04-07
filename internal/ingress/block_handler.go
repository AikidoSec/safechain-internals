package ingress

import (
	"encoding/json"
	"log"
	"net/http"
)

func (s *Server) handleBlock(w http.ResponseWriter, r *http.Request) {
	var event BlockEvent
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	log.Println("Got block event:", event)

	if event.Artifact.Product == "chrome" {
		if s.eventStore.MergeChromeBlockIfDuplicate(event) {
			w.WriteHeader(http.StatusOK)
			return
		}
	}

	blocked := s.eventStore.Add(event)
	go s.ui.NotifyBlocked(blocked)

	w.WriteHeader(http.StatusOK)
}
