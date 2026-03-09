package ingress

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	"github.com/AikidoSec/safechain-internals/internal/cloud"
)

func (s *Server) handleRequestBypass(w http.ResponseWriter, r *http.Request) {
	var req RequestBypassEvent
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	log.Printf("Received request-bypass event: key=%s", req.Key)

	s.blocksMu.RLock()
	event, found := s.recentBlocks[req.Key]
	s.blocksMu.RUnlock()

	if found && event.BlockReason == "request_install" {
		go s.sendInstallationRequest(event)
	}

	w.WriteHeader(http.StatusOK)
}

func (s *Server) sendInstallationRequest(event BlockEvent) {
	installEvent := buildInstallationRequestEvent(event)
	if err := cloud.SendRequestPackageInstallation(context.Background(), s.config, installEvent); err != nil {
		log.Printf("Failed to send installation request for %s: %v", buildKey(event), err)
		return
	}
	log.Printf("Installation request sent for %s", buildKey(event))
}

func buildInstallationRequestEvent(event BlockEvent) *cloud.RequestPackageInstallationEvent {
	pkg := cloud.PackageInstallRequest{
		ID:      event.Artifact.PackageName,
		Name:    event.Artifact.PackageName,
		Version: event.Artifact.PackageVersion,
	}
	var installEvent cloud.RequestPackageInstallationEvent
	installEvent.SBOM.Ecosystems = []cloud.EcosystemPackages{
		{
			Variant:  event.Artifact.Product,
			Packages: []cloud.PackageInstallRequest{pkg},
		},
	}
	return &installEvent
}
