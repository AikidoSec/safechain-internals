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

func (s *Server) sendInstallationRequest(event BlockedEvent) {
	req := RequestBypassEvent{
		Key:            event.ID,
		Product:        event.Product,
		PackageName:    event.PackageName,
		PackageVersion: event.PackageVersion,
	}
	installEvent := buildInstallationRequestEvent(req)
	if err := cloud.SendRequestPackageInstallation(context.Background(), s.config, installEvent); err != nil {
		log.Printf("Failed to send installation request for %s: %v", req.Key, err)
		return
	}
	log.Printf("Installation request sent for %s", req.Key)
}

func buildInstallationRequestEvent(req RequestBypassEvent) *cloud.RequestPackageInstallationEvent {
	pkg := cloud.PackageInstallRequest{
		ID:      req.PackageName,
		Name:    req.PackageName,
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