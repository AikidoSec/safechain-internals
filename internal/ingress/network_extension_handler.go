package ingress

import (
	"encoding/json"
	"log"
	"net/http"
)

type NetworkExtensionResult struct {
	Status string `json:"status"`
}

func (s *Server) handleNetworkExtensionActivate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.validateUIToken(w, r) {
		return
	}
	status, err := activateNetworkExtension(r.Context())
	if err != nil {
		log.Printf("ingress: network extension activate: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(NetworkExtensionResult{Status: status}); err != nil {
		log.Printf("ingress: network extension activate encode: %v", err)
	}
}

func (s *Server) handleNetworkExtensionOpenSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.validateUIToken(w, r) {
		return
	}
	if err := openNetworkExtensionSettings(r.Context()); err != nil {
		log.Printf("ingress: network extension open-settings: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleNetworkExtensionAllowVpn(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.validateUIToken(w, r) {
		return
	}
	status, err := allowNetworkExtensionVpn(r.Context())
	if err != nil {
		log.Printf("ingress: network extension allow-vpn: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(NetworkExtensionResult{Status: status}); err != nil {
		log.Printf("ingress: network extension allow-vpn encode: %v", err)
	}
}
