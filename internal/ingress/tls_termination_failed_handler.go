package ingress

import (
	"encoding/json"
	"log"
	"net/http"
)

func (s *Server) handleTlsTerminationFailed(w http.ResponseWriter, r *http.Request) {
	var event TlsTerminationFailedEvent
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	log.Printf("TLS termination failed: sni=%s app=%s error=%s", event.SNI, event.App, event.Error)

	stored := s.tlsEventStore.Add(event)
	go s.ui.NotifyTlsTerminationFailed(stored)

	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleTlsEvents(w http.ResponseWriter, r *http.Request) {
	if !s.validateUIToken(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(s.tlsEventStore.List()); err != nil {
		log.Printf("failed to encode TLS events: %v", err)
	}
}

func (s *Server) handleGetTlsEventByID(w http.ResponseWriter, r *http.Request) {
	if !s.validateUIToken(w, r) {
		return
	}
	id := r.PathValue("id")
	if event, ok := s.tlsEventStore.Get(id); ok {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(event); err != nil {
			log.Printf("failed to encode TLS event %s: %v", id, err)
		}
		return
	}
	w.WriteHeader(http.StatusNotFound)
	if _, err := w.Write([]byte("Event not found")); err != nil {
		log.Printf("failed to write 404 response: %v", err)
	}
}
