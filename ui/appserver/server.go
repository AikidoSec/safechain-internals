package appserver

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"

	"changeme/daemon"
)

// ListenAddr is the address the app server listens on. Set via SetListenAddr (e.g. from -ui_url flag).
// Daemon should call: POST <ListenAddr>/v1/proxy-status and POST <ListenAddr>/v1/blocked
var ListenAddr = "127.0.0.1:9876"

// SetListenAddr sets the address the app server listens on. Call at startup before Start (e.g. from -ui_url).
func SetListenAddr(addr string) {
	if addr != "" {
		ListenAddr = addr
	}
}

// validateToken returns true if the request has a valid Authorization: Bearer <token> matching daemon.TOKEN.
// If invalid, it writes 401 and returns false.
func validateToken(w http.ResponseWriter, r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	token := strings.TrimPrefix(auth, "Bearer ")
	if token != daemon.TOKEN {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

// ProxyStatusBody is the JSON body for POST /v1/proxy-status.
type ProxyStatusBody struct {
	Running bool `json:"running"`
}

// Server receives status and block events from the daemon.
type Server struct {
	mu sync.Mutex

	onStatusUpdate func(displayLabel string)    // called when daemon posts new status (tray update)
	onBlocked      func(ev daemon.BlockedEvent) // called when daemon posts a new block
}

// New creates a new app server. Handlers are set via SetHandlers before Start.
func New() *Server {
	return &Server{}
}

// SetHandlers sets the callbacks for status updates and blocked events.
func (s *Server) SetHandlers(onStatus func(string), onBlocked func(daemon.BlockedEvent)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onStatusUpdate = onStatus
	s.onBlocked = onBlocked
}

// Start starts the HTTP server in a goroutine. Call from main after setting handlers.
func (s *Server) Start() {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/proxy-status", s.handleProxyStatus)
	mux.HandleFunc("POST /v1/blocked", s.handleBlocked)

	go func() {
		if err := http.ListenAndServe(ListenAddr, mux); err != nil && err != http.ErrServerClosed {
			log.Printf("app server: %v", err)
		}
	}()
}

func (s *Server) handleProxyStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
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
	displayLabel := "⚫ Aikido Proxy is not reachable"
	if body.Running {
		displayLabel = "🟢 Aikido Proxy is running"
	} else {
		displayLabel = "🔴 Aikido Proxy is stopped"
	}
	cb(displayLabel)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleBlocked(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !validateToken(w, r) {
		return
	}
	var ev daemon.BlockedEvent
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
