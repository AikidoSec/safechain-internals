package ingress

import (
	"encoding/json"
	"log"
	"net/http"
)

func (s *Server) handleRequestBypass(w http.ResponseWriter, r *http.Request) {
	if !validateUIToken(w, r) {
		return
	}
	id := r.PathValue("id")
	event, ok := s.eventStore.Get(id)
	if !ok {
		http.Error(w, "event not found", http.StatusNotFound)
		return
	}

	log.Printf("Received request-bypass event: key=%s", event.ID)

	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if !validateUIToken(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(s.eventStore.List())
}

func (s *Server) handleGetEventByID(w http.ResponseWriter, r *http.Request) {
	if !validateUIToken(w, r) {
		return
	}
	id := r.PathValue("id")
	if event, ok := s.eventStore.Get(id); ok {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(event)
		return
	}
	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte("Event not found"))
}
