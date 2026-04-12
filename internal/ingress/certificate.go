package ingress

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/AikidoSec/safechain-internals/internal/certconfig"
	"github.com/AikidoSec/safechain-internals/internal/proxy"
)

type CertificateStatus struct {
	NeedsInstall bool `json:"needs_install"`
	Installed    bool `json:"installed"`
}

func (s *Server) handleCertificateStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.validateUIToken(w, r) {
		return
	}
	caTrusted := proxy.ProxyCAInstalled()
	proxyRunning := s.proxy != nil && s.proxy.IsRunning()
	st := CertificateStatus{
		NeedsInstall: proxyRunning && !caTrusted,
		Installed:    caTrusted,
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(st); err != nil {
		log.Printf("ingress: certificate status encode: %v", err)
	}
}

func (s *Server) handleCertificateInstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.validateUIToken(w, r) {
		return
	}
	if s.proxy == nil {
		http.Error(w, "certificate API not configured", http.StatusServiceUnavailable)
		return
	}
	if err := s.proxy.InstallCA(r.Context()); err != nil {
		log.Printf("ingress: certificate install: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := certconfig.Install(r.Context()); err != nil {
		log.Printf("ingress: certconfig install: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}
