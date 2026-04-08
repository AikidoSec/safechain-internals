// mock/main.go — lightweight mock daemon for UI development.
//
// Serves the same endpoints the real daemon exposes so the UI can
// connect and render without running the full agent stack.
//
// Usage:
//
//	go run ./mock
//	# then in another terminal:
//	task dev            (UI connects to 127.0.0.1:7878 by default)
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

// ── data models (mirrors daemon/types.go) ────────────────────────────

type Artifact struct {
	Product     string `json:"product"`
	Identifier  string `json:"identifier"`
	Version     string `json:"version,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
}

type BlockEvent struct {
	ID          string   `json:"id"`
	TsMs        int64    `json:"ts_ms"`
	Artifact    Artifact `json:"artifact"`
	BlockReason string   `json:"block_reason"`
	Status      string   `json:"status"`
	Count       int      `json:"count"`
}

type TlsEvent struct {
	ID    string `json:"id"`
	TsMs  int64  `json:"ts_ms"`
	SNI   string `json:"sni"`
	App   string `json:"app,omitempty"`
	Error string `json:"error"`
}

// ── seed data ────────────────────────────────────────────────────────

func seedData() ([]BlockEvent, []TlsEvent) {
	now := time.Now().UnixMilli()

	blocks := []BlockEvent{
		{
			ID:          "block-1",
			TsMs:        now - 60_000,
			Artifact:    Artifact{Product: "chrome", Identifier: "mgngmngjioknlgjjaiiamcdbahombpfb", Version: "1.0.0", DisplayName: ""},
			BlockReason: "malware",
			Status:      "blocked",
			Count:       13,
		},
		{
			ID:          "block-2",
			TsMs:        now - 120_000,
			Artifact:    Artifact{Product: "pypi", Identifier: "shady-lib", Version: "0.3.1", DisplayName: "shady-lib"},
			BlockReason: "rejected",
			Status:      "blocked",
			Count:       1,
		},
		{
			ID:          "block-3",
			TsMs:        now - 300_000,
			Artifact:    Artifact{Product: "vscode", Identifier: "typosquat-pkg", Version: "2.0.0", DisplayName: "typosquat-pkg"},
			BlockReason: "block_all",
			Status:      "blocked",
			Count:       1,
		},
		{
			ID:          "block-4",
			TsMs:        now - 45_000,
			Artifact:    Artifact{Product: "maven", Identifier: "left-pad", Version: "1.3.0", DisplayName: "left-pad"},
			BlockReason: "request_install",
			Status:      "blocked",
			Count:       1,
		},
		{
			ID:          "block-5",
			TsMs:        now - 90_000,
			Artifact:    Artifact{Product: "npm", Identifier: "brand-new-lib", Version: "0.0.2", DisplayName: "brand-new-lib"},
			BlockReason: "new_package",
			Status:      "blocked",
			Count:       1,
		},
		{
			ID:          "block-6",
			TsMs:        now - 15_000,
			Artifact:    Artifact{Product: "nuget", Identifier: "Contoso.Analytics", Version: "3.1.0", DisplayName: "Contoso.Analytics"},
			BlockReason: "request_install",
			Status:      "request_pending",
			Count:       1,
		},
		{
			ID:          "block-7",
			TsMs:        now - 360_000,
			Artifact:    Artifact{Product: "chrome", Identifier: "pgojnojmmhpofjgdmaebadhbocahppod", Version: "", DisplayName: ""},
			BlockReason: "request_install",
			Status:      "request_approved",
			Count:       32,
		},
		{
			ID:          "block-8",
			TsMs:        now - 400_000,
			Artifact:    Artifact{Product: "open_vsx", Identifier: "ms-python.python", Version: "2024.0.0", DisplayName: "Python"},
			BlockReason: "request_install",
			Status:      "request_rejected",
			Count:       1,
		},
		{
			ID:          "block-5",
			TsMs:        now - 90_000,
			Artifact:    Artifact{Product: "npm", Identifier: "brand-new-lib", Version: "0.0.2", DisplayName: "brand-new-lib"},
			BlockReason: "new_package",
			Status:      "blocked",
		},
	}

	tlsEvents := []TlsEvent{
		{
			ID:    "tls-1",
			TsMs:  now - 30_000,
			SNI:   "pinned.example.com",
			App:   "Safari",
			Error: "certificate pinning verification failed: peer certificate does not match any pinned certificate",
		},
		{
			ID:    "tls-2",
			TsMs:  now - 180_000,
			SNI:   "api.internal.corp",
			App:   "curl",
			Error: "tls: server selected unsupported protocol version 301",
		},
	}

	return blocks, tlsEvents
}

type EcosystemExceptions struct {
	AllowedPackages  []string `json:"allowed_packages"`
	RejectedPackages []string `json:"rejected_packages"`
}

type EcosystemPermissions struct {
	BlockAllInstalls           bool                `json:"block_all_installs"`
	RequestInstalls            bool                `json:"request_installs"`
	MinimumAllowedAgeTimestamp int64               `json:"minimum_allowed_age_timestamp"`
	Exceptions                 EcosystemExceptions `json:"exceptions"`
}

type PermissionsResponse struct {
	PermissionGroup struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	} `json:"permission_group"`
	Ecosystems map[string]EcosystemPermissions `json:"ecosystems"`
}

func seedPermissions() PermissionsResponse {
	return PermissionsResponse{
		PermissionGroup: struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
		}{ID: 5, Name: "Engineering"},
		Ecosystems: map[string]EcosystemPermissions{
			"npm": {
				BlockAllInstalls:           false,
				RequestInstalls:            true,
				MinimumAllowedAgeTimestamp: 1740000000,
				Exceptions: EcosystemExceptions{
					AllowedPackages:  []string{"left-pad"},
					RejectedPackages: []string{},
				},
			},
		},
	}
}

// ── server ───────────────────────────────────────────────────────────

type server struct {
	mu                   sync.RWMutex
	blocks               []BlockEvent
	tlsEvents            []TlsEvent
	permissions          PermissionsResponse
	extensionActivated   bool
	vpnAllowed           bool
	token                string
}

func (s *server) writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("mock: failed to write response: %v", err)
	}
}

func (s *server) handleVersion(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, map[string]string{"version": "1.2.3"})
}

func (s *server) handleListEvents(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	s.writeJSON(w, s.blocks)
}

func (s *server) handleGetEvent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.blocks {
		if e.ID == id {
			s.writeJSON(w, e)
			return
		}
	}
	http.NotFound(w, r)
}

func (s *server) handleListTlsEvents(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	s.writeJSON(w, s.tlsEvents)
}

func (s *server) handleGetTlsEvent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.tlsEvents {
		if e.ID == id {
			s.writeJSON(w, e)
			return
		}
	}
	http.NotFound(w, r)
}

func (s *server) handlePermissions(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	s.writeJSON(w, s.permissions)
}

func (s *server) handleRequestAccess(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, e := range s.blocks {
		if e.ID == id {
			s.blocks[i].Status = "request_pending"
			log.Printf("mock: request-access for %s → status=request_pending", id)
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
	http.NotFound(w, r)
}

func (s *server) handleCertificateStatus(w http.ResponseWriter, r *http.Request) {
	// Mock: pretend CA is already installed so the install window stays hidden during UI dev.
	s.writeJSON(w, map[string]bool{"needs_install": false, "installed": true})
}

func (s *server) handleCertificateInstall(w http.ResponseWriter, r *http.Request) {
	log.Println("mock: certificate install (simulated 2s delay)")
	time.Sleep(2 * time.Second)
	w.WriteHeader(http.StatusOK)
}

func (s *server) handleNetworkExtensionActivate(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.extensionActivated = true
	s.mu.Unlock()
	log.Println("mock: network extension activated")
	s.writeJSON(w, map[string]string{"status": "activated"})
}

func (s *server) handleNetworkExtensionAllowVpn(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.vpnAllowed = true
	s.mu.Unlock()
	log.Println("mock: vpn allowed")
	s.writeJSON(w, map[string]string{"status": "allowed"})
}

func (s *server) handleNetworkExtensionOpenSettings(w http.ResponseWriter, r *http.Request) {
	log.Println("mock: open network extension settings (no-op)")
	w.WriteHeader(http.StatusOK)
}

func (s *server) handleIsExtensionActivated(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	activated := s.extensionActivated
	s.mu.RUnlock()
	s.writeJSON(w, map[string]bool{"result": activated})
}

func (s *server) handleIsVpnAllowed(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	allowed := s.vpnAllowed
	s.mu.RUnlock()
	s.writeJSON(w, map[string]bool{"result": allowed})
}

func (s *server) handleProxyStart(w http.ResponseWriter, r *http.Request) {
	log.Println("mock: proxy started")
	w.WriteHeader(http.StatusOK)
}

func (s *server) handleSetToken(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.token = body.Token
	s.mu.Unlock()
	log.Printf("mock: token set to %q", body.Token)
	w.WriteHeader(http.StatusOK)
}

func (s *server) handleSetupCheck(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var steps []string
	if s.token == "" {
		steps = append(steps, "token")
	}
	if !s.extensionActivated {
		steps = append(steps, "activate-extension")
	}
	if !s.vpnAllowed {
		steps = append(steps, "allow-vpn")
	}
	if len(steps) > 0 {
		steps = append(steps, "start-proxy", "install-ca")
	}
	if len(steps) == 0 {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusConflict)
	json.NewEncoder(w).Encode(map[string][]string{"steps": steps})
}

func (s *server) handleSetupStart(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var steps []string
	if s.token == "" {
		steps = append(steps, "token")
	}
	if !s.extensionActivated {
		steps = append(steps, "activate-extension")
	}
	if !s.vpnAllowed {
		steps = append(steps, "allow-vpn")
	}
	if len(steps) > 0 {
		steps = append(steps, "start-proxy", "install-ca")
	}
	log.Printf("mock: setup start → steps=%v", steps)
	s.writeJSON(w, map[string][]string{"steps": steps})
}

func main() {
	blocks, tlsEvents := seedData()
	s := &server{blocks: blocks, tlsEvents: tlsEvents, permissions: seedPermissions()}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/version", s.handleVersion)
	mux.HandleFunc("GET /v1/events", s.handleListEvents)
	mux.HandleFunc("GET /v1/events/{id}", s.handleGetEvent)
	mux.HandleFunc("GET /v1/tls-events", s.handleListTlsEvents)
	mux.HandleFunc("GET /v1/tls-events/{id}", s.handleGetTlsEvent)
	mux.HandleFunc("GET /v1/permissions", s.handlePermissions)
	mux.HandleFunc("POST /v1/events/{id}/request-access", s.handleRequestAccess)
	mux.HandleFunc("GET /v1/certificate/status", s.handleCertificateStatus)
	mux.HandleFunc("POST /v1/certificate/install", s.handleCertificateInstall)

	mux.HandleFunc("POST /v1/network-extension/activate", s.handleNetworkExtensionActivate)
	mux.HandleFunc("POST /v1/network-extension/allow-vpn", s.handleNetworkExtensionAllowVpn)
	mux.HandleFunc("POST /v1/network-extension/open-settings", s.handleNetworkExtensionOpenSettings)
	mux.HandleFunc("GET /v1/network-extension/is-activated", s.handleIsExtensionActivated)
	mux.HandleFunc("GET /v1/network-extension/is-vpn-allowed", s.handleIsVpnAllowed)

	mux.HandleFunc("POST /v1/proxy/start", s.handleProxyStart)
	mux.HandleFunc("POST /v1/token", s.handleSetToken)

	mux.HandleFunc("GET /v1/setup/check", s.handleSetupCheck)
	mux.HandleFunc("POST /v1/setup/start", s.handleSetupStart)

	addr := "127.0.0.1:7878"
	fmt.Printf("Mock daemon listening on %s\n", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
