package appserver

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"

	"endpoint-protection-ui/daemon"
)

var ListenAddr = "127.0.0.1:9876"

func SetListenAddr(addr string) {
	if addr != "" {
		ListenAddr = addr
	}
}

func validateToken(w http.ResponseWriter, r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	token := strings.TrimPrefix(auth, "Bearer ")
	if token != daemon.AgentConfig.Token {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

type ProxyStatusBody struct {
	Running       bool   `json:"running"`
	StdoutMessage string `json:"stdout_message"`
}

// Server receives proxy-status and block events from the daemon via HTTP.
type Server struct {
	mu                     sync.Mutex
	onStatusUpdate         func(ev ProxyStatusBody)
	onBlocked              func(ev daemon.BlockEvent)
	onTlsTerminationFailed func(ev daemon.TlsTerminationFailedEvent)
	onPermissionsUpdated   func(ev daemon.PermissionsResponse)
	onSetupWizard          func(steps []string)
}

func New() *Server {
	return &Server{}
}

func (s *Server) SetHandlers(
	onStatus func(ev ProxyStatusBody),
	onBlocked func(daemon.BlockEvent),
	onTlsTerminationFailed func(daemon.TlsTerminationFailedEvent),
	onPermissionsUpdated func(daemon.PermissionsResponse),
	onSetupWizard func(steps []string),
) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onStatusUpdate = onStatus
	s.onBlocked = onBlocked
	s.onTlsTerminationFailed = onTlsTerminationFailed
	s.onPermissionsUpdated = onPermissionsUpdated
	s.onSetupWizard = onSetupWizard
}

// Start launches the HTTP server in a background goroutine.
func (s *Server) Start() {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/proxy-status", s.handleProxyStatus)
	mux.HandleFunc("POST /v1/blocked", s.handleBlocked)
	mux.HandleFunc("POST /v1/tls-termination-failed", s.handleTlsTerminationFailed)
	mux.HandleFunc("POST /v1/permissions", s.handlePermissionsUpdated)
	mux.HandleFunc("POST /v1/setup-wizard", s.handleSetupWizard)

	go func() {
		if err := http.ListenAndServe(ListenAddr, mux); err != nil && err != http.ErrServerClosed {
			log.Printf("app server: %v", err)
		}
	}()
}

func (s *Server) handleProxyStatus(w http.ResponseWriter, r *http.Request) {
	if !validateToken(w, r) {
		return
	}
	var body ProxyStatusBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	cb := s.onStatusUpdate
	s.mu.Unlock()
	if cb == nil {
		w.WriteHeader(http.StatusOK)
		return
	}
	cb(body)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleBlocked(w http.ResponseWriter, r *http.Request) {
	if !validateToken(w, r) {
		return
	}
	var ev daemon.BlockEvent
	if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if err := ev.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	cb := s.onBlocked
	s.mu.Unlock()
	if cb != nil {
		cb(ev)
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handlePermissionsUpdated(w http.ResponseWriter, r *http.Request) {
	if !validateToken(w, r) {
		return
	}
	var ev daemon.PermissionsResponse
	if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	cb := s.onPermissionsUpdated
	s.mu.Unlock()
	if cb != nil {
		cb(ev)
	}
	w.WriteHeader(http.StatusOK)
}

type setupWizardBody struct {
	Steps []string `json:"steps"`
}

func (s *Server) handleSetupWizard(w http.ResponseWriter, r *http.Request) {
	if !validateToken(w, r) {
		return
	}
	var body setupWizardBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	cb := s.onSetupWizard
	s.mu.Unlock()
	if cb != nil {
		cb(body.Steps)
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleTlsTerminationFailed(w http.ResponseWriter, r *http.Request) {
	if !validateToken(w, r) {
		return
	}
	var ev daemon.TlsTerminationFailedEvent
	if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if err := ev.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	cb := s.onTlsTerminationFailed
	s.mu.Unlock()
	if cb != nil {
		cb(ev)
	}
	w.WriteHeader(http.StatusOK)
}
