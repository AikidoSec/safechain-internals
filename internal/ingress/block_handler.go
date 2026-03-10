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
	log.Printf("Received block event: %+v", event)

	blocked := s.eventStore.Add(event)
	go s.ui.NotifyBlocked(blocked)

	w.WriteHeader(http.StatusOK)
}

// BlockedEvent matches the daemon API response.
type BlockedEvent struct {
	ID             string      `json:"id"`
	Ts             string      `json:"ts"`
	Product        string      `json:"product"`
	PackageName    string      `json:"identifier"`
	PackageVersion string      `json:"version,omitempty"`
	BlockReason    BlockReason `json:"block_reason"`
	Status         string      `json:"status,omitempty"`
}
