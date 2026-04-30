package ingress

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/AikidoSec/safechain-internals/internal/cloud"
	"github.com/AikidoSec/safechain-internals/internal/sbom"
	"github.com/AikidoSec/safechain-internals/internal/version"
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

	if shouldDelayBlockedUINotification(blocked) {
		go func() {
			enriched := s.enrichChromeBlockDisplayName(blocked)
			s.ui.NotifyBlocked(enriched)
			s.sendBlockedActivity(enriched)
		}()
	} else {
		go s.ui.NotifyBlocked(blocked)
		go s.sendBlockedActivity(blocked)
	}

	w.WriteHeader(http.StatusOK)
}

func shouldDelayBlockedUINotification(event BlockEvent) bool {
	return event.Artifact.Product == "chrome" && event.Artifact.DisplayName == ""
}

func (s *Server) enrichChromeBlockDisplayName(event BlockEvent) BlockEvent {
	if event.Artifact.Product != "chrome" || event.Artifact.DisplayName != "" {
		return event
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	displayName, err := s.chromeNames.Lookup(ctx, event.Artifact.PackageName)
	if err != nil {
		log.Printf("failed to look up Chrome extension display name for %s: %v", event.Artifact.PackageName, err)
		return event
	}
	if displayName == "" {
		return event
	}

	updated, ok := s.eventStore.UpdateDisplayName(event.ID, displayName)
	if !ok {
		return event
	}

	log.Printf("updated Chrome extension display name for %s: %q", event.Artifact.PackageName, displayName)
	return updated
}

func (s *Server) sendBlockedActivity(event BlockEvent) {
	action, ok := mapBlockReasonToActivityAction(event.BlockReason)
	if !ok {
		log.Printf("skipping block activity upload for unsupported block reason %q", event.BlockReason)
		return
	}

	activityEvent := buildBlockedActivityEvent(event, action)
	if err := cloud.SendActivity(context.Background(), s.config, activityEvent); err != nil {
		log.Printf("failed to send blocked activity for %s: %v", event.ID, err)
		return
	}

	log.Printf("blocked activity sent for %s with action=%s", event.ID, action)
}

func mapBlockReasonToActivityAction(reason string) (string, bool) {
	switch reason {
	case "malware":
		return "malware_blocked", true
	case "rejected", "block_all", "request_install", "new_package":
		return "install_blocked", true
	default:
		return "", false
	}
}

func buildBlockedActivityEvent(event BlockEvent, action string) *cloud.ActivityEvent {
	name := event.Artifact.DisplayName
	if name == "" {
		name = event.Artifact.PackageName
	}

	return &cloud.ActivityEvent{
		Action:      action,
		VersionInfo: *version.Info,
		SBOM: sbom.SBOM{
			Entries: []sbom.EcosystemEntry{
				{
					Ecosystem: event.Artifact.Product,
					Packages: []sbom.Package{
						{
							Id:      event.Artifact.PackageName,
							Name:    name,
							Version: event.Artifact.PackageVersion,
						},
					},
				},
			},
		},
	}
}
