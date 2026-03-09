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

	go s.sendInstallationRequest(req)

	w.WriteHeader(http.StatusOK)
}

func (s *Server) sendInstallationRequest(req RequestBypassEvent) {
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
			Variant:  req.Product,
			Packages: []cloud.PackageInstallRequest{pkg},
		},
	}
	return &installEvent
}
