package ingress

import (
	"encoding/json"
	"log"
	"net/http"
)

func (s *Server) handleMinPackageAge(w http.ResponseWriter, r *http.Request) {
	var event MinPackageAgeEvent
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	log.Println("Got min-package-age event:", event)

	stored := s.minAgeStore.Add(event)

	// These events are informational only: they should show up in the Logs tab,
	// but must not create a native popup notification.
	go s.ui.NotifyMinPackageAge(stored)

	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleMinPackageAgeEvents(w http.ResponseWriter, r *http.Request) {
	if !s.validateUIToken(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(s.minAgeStore.List()); err != nil {
		log.Printf("failed to encode min-package-age events: %v", err)
	}
}

func (s *Server) handleGetMinPackageAgeEventByID(w http.ResponseWriter, r *http.Request) {
	if !s.validateUIToken(w, r) {
		return
	}
	id := r.PathValue("id")
	if event, ok := s.minAgeStore.Get(id); ok {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(event); err != nil {
			log.Printf("failed to encode min-package-age event %s: %v", id, err)
		}
		return
	}
	w.WriteHeader(http.StatusNotFound)
	if _, err := w.Write([]byte("Event not found")); err != nil {
		log.Printf("failed to write 404 response: %v", err)
	}
}
