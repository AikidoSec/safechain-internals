package ingress

import (
	"encoding/json"
	"net/http"
)

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if !s.validateUIToken(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(s.eventStore.List())
}

func (s *Server) handleGetEventByID(w http.ResponseWriter, r *http.Request) {
	if !s.validateUIToken(w, r) {
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
