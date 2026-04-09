package ingress

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
)

// CertificateStatus is returned by GET /v1/certificate/status for the tray UI.
type CertificateStatus struct {
	NeedsInstall bool `json:"needs_install"`
	Installed    bool `json:"installed"`
}

// SetCertificateHandlers wires proxy CA checks and installation into the ingress API.
// Both callbacks must be non-nil for the routes to succeed.
func (s *Server) SetCertificateHandlers(status func() CertificateStatus, install func(context.Context) error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.certStatus = status
	s.certInstall = install
}

func (s *Server) handleCertificateStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.validateUIToken(w, r) {
		return
	}
	s.mu.RLock()
	fn := s.certStatus
	s.mu.RUnlock()
	if fn == nil {
		http.Error(w, "certificate API not configured", http.StatusServiceUnavailable)
		return
	}
	st := fn()
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
	s.mu.RLock()
	install := s.certInstall
	s.mu.RUnlock()
	if install == nil {
		http.Error(w, "certificate API not configured", http.StatusServiceUnavailable)
		return
	}
	if err := install(r.Context()); err != nil {
		log.Printf("ingress: certificate install: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}
