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

	log.Printf("Received request-bypass event: key=%s", event.ID)
	s.eventStore.UpdateStatus(id, "request_pending")

	go s.sendInstallationRequest(event)

	w.WriteHeader(http.StatusOK)
}

func (s *Server) sendInstallationRequest(event BlockEvent) {
	req := RequestBypassEvent{
		Key:            event.ID,
		Product:        event.Artifact.Product,
		PackageName:    event.Artifact.PackageName,
		PackageVersion: event.Artifact.PackageVersion,
	}
	installEvent := buildInstallationRequestEvent(req)
	if err := cloud.SendRequestPackageInstallation(context.Background(), s.config, installEvent); err != nil {
		log.Printf("Failed to send installation request for %s: %v", req.PackageId, err)
		return
	}
	log.Printf("Installation request sent for %s", req.PackageId)
}

func buildInstallationRequestEvent(req RequestBypassEvent) *cloud.RequestPackageInstallationEvent {
	name := req.PackageName
	if name == "" {
		name = req.PackageId
	}
	pkg := cloud.PackageInstallRequest{
		ID:      req.PackageId,
		Name:    name,
		Version: req.PackageVersion,
	}
	var installEvent cloud.RequestPackageInstallationEvent
	installEvent.SBOM.Ecosystems = []cloud.EcosystemPackages{
		{
			Ecosystem: req.Product,
			Packages:  []cloud.PackageInstallRequest{pkg},
		},
	}
	return &installEvent
}
