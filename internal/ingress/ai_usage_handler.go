package ingress

import (
	"encoding/json"
	"log"
	"net/http"
)

func (s *Server) handleAiUsage(w http.ResponseWriter, r *http.Request) {
	log.Printf("ai-usage: POST /events/ai-usage from %s", r.RemoteAddr)

	var event AiUsageEvent
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		log.Printf("ai-usage: invalid JSON body: %v", err)
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if event.Provider == "" || event.Model == "" {
		log.Printf("ai-usage: rejecting event with missing fields: provider=%q model=%q", event.Provider, event.Model)
		http.Error(w, "provider and model are required", http.StatusBadRequest)
		return
	}

	stored, isNew := s.aiUsageStore.Add(event)
	if isNew {
		log.Printf("ai-usage: first observation: provider=%s model=%s", stored.Provider, stored.Model)
	} else {
		log.Printf("ai-usage: repeat observation: provider=%s model=%s", stored.Provider, stored.Model)
	}

	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleAiUsageEvents(w http.ResponseWriter, r *http.Request) {
	if !s.validateUIToken(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(s.aiUsageStore.List()); err != nil {
		log.Printf("failed to encode ai-usage events: %v", err)
	}
}
