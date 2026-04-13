package ingress

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"
)

func (s *Server) handleBlock(w http.ResponseWriter, r *http.Request) {
	var event BlockEvent
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	log.Println("Got block event:", event)

	if event.Artifact.Product == "chrome" && event.Artifact.DisplayName == "" {
		ctx, cancel := context.WithTimeout(r.Context(), 750*time.Millisecond)
		displayName, err := s.chromeNames.Lookup(ctx, event.Artifact.PackageName)
		cancel()
		if err != nil {
			log.Printf("failed to look up Chrome extension display name for %s: %v", event.Artifact.PackageName, err)
		} else {
			if displayName != "" {
				event.Artifact.DisplayName = displayName
			}
		}
	}

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
