package ingress

import (
	"context"
	"log"
	"net/http"

	"github.com/AikidoSec/safechain-internals/internal/cloud"
)

func (s *Server) handleRequestBypass(w http.ResponseWriter, r *http.Request) {
	if !s.validateUIToken(w, r) {
		return
	}
	id := r.PathValue("id")
	event, ok := s.eventStore.Get(id)
	if !ok {
		http.Error(w, "event not found", http.StatusNotFound)
		return
	}

	log.Printf("Received request-bypass event: name=%s, version=%s, product=%s", event.Artifact.PackageName, event.Artifact.PackageVersion, event.Artifact.Product)

	for _, e := range s.eventStore.List() {
		if e.Artifact.SameIdentity(event.Artifact) {
			s.eventStore.UpdateStatus(e.ID, "pending")
		}
	}

	go s.sendInstallationRequest(event)

	w.WriteHeader(http.StatusOK)
}

func (s *Server) sendInstallationRequest(event BlockEvent) {
	installEvent := buildInstallationRequestEvent(event)
	if err := cloud.SendRequestPackageInstallation(context.Background(), s.config, installEvent); err != nil {
		log.Printf("Failed to send installation request for %s: %v", event.ID, err)
		return
	}
	log.Printf("Installation request sent for %s", event.ID)
}

func buildInstallationRequestEvent(event BlockEvent) *cloud.RequestPackageInstallationEvent {
	name := event.Artifact.DisplayName
	if name == "" {
		name = event.Artifact.PackageName
	}
	pkg := cloud.PackageInstallRequest{
		ID:      event.Artifact.PackageName,
		Name:    name,
		Version: event.Artifact.PackageVersion,
	}
	var installEvent cloud.RequestPackageInstallationEvent
	installEvent.SBOM.Ecosystems = []cloud.EcosystemPackages{
		{
			Ecosystem: event.Artifact.Product,
			Packages:  []cloud.PackageInstallRequest{pkg},
		},
	}
	return &installEvent
}
