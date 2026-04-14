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

	if event.Artifact.Product == "chrome" {
		if s.eventStore.MergeChromeBlockIfDuplicate(event) {
			w.WriteHeader(http.StatusOK)
			return
		}
	}

	blocked := s.eventStore.Add(event)
	go s.ui.NotifyBlocked(blocked)
	if blocked.Artifact.Product == "chrome" && blocked.Artifact.DisplayName == "" {
		go s.enrichChromeBlockDisplayName(blocked)
	}

	w.WriteHeader(http.StatusOK)
}

func (s *Server) enrichChromeBlockDisplayName(event BlockEvent) {
	if event.Artifact.Product != "chrome" || event.Artifact.DisplayName != "" {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	displayName, err := s.chromeNames.Lookup(ctx, event.Artifact.PackageName)
	if err != nil {
		log.Printf("failed to look up Chrome extension display name for %s: %v", event.Artifact.PackageName, err)
		return
	}
	if displayName == "" {
		return
	}

	updated, ok := s.eventStore.UpdateDisplayName(event.ID, displayName)
	if !ok {
		return
	}

	log.Printf("updated Chrome extension display name for %s: %q", event.Artifact.PackageName, displayName)
	s.ui.NotifyBlockedUpdated(updated)
}
