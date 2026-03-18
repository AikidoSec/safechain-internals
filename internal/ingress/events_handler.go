package ingress

import (
	"encoding/json"
	"log"
	"net/http"
)

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if !s.validateUIToken(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(s.eventStore.List()); err != nil {
		log.Printf("failed to encode events: %v", err)
	}
}

func (s *Server) handleGetEventByID(w http.ResponseWriter, r *http.Request) {
	if !s.validateUIToken(w, r) {
		return
	}
	id := r.PathValue("id")
	if event, ok := s.eventStore.Get(id); ok {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(event); err != nil {
			log.Printf("failed to encode event %s: %v", id, err)
		}
		return
	}
	w.WriteHeader(http.StatusNotFound)
	if _, err := w.Write([]byte("Event not found")); err != nil {
		log.Printf("failed to write 404 response: %v", err)
	}
}
