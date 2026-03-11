package appserver

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"

	"safechain-ui/daemon"
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
	Running bool `json:"running"`
}

// Server receives proxy-status and block events from the daemon via HTTP.
type Server struct {
	mu             sync.Mutex
	onStatusUpdate func(displayLabel string)
	onBlocked      func(ev daemon.BlockEvent)
}

func New() *Server {
	return &Server{}
}

func (s *Server) SetHandlers(onStatus func(string), onBlocked func(daemon.BlockEvent)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onStatusUpdate = onStatus
	s.onBlocked = onBlocked
}

// Start launches the HTTP server in a background goroutine.
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
