// Package ingress provides an HTTP server that receives events from the proxy
// and handles them appropriately (e.g., showing UI modals for blocked packages).
package ingress

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"

	"github.com/AikidoSec/safechain-internals/internal/config"
	"github.com/AikidoSec/safechain-internals/internal/proxy"
)

const (
	DefaultBind = "127.0.0.1:0" // Use port 0 to let the OS assign a free port
)

// UIProvider abstracts the UI capabilities needed by the ingress server:
// authenticating inbound requests and forwarding block notifications.
type UIProvider interface {
	Token() string
	NotifyBlocked(ev any)
	NotifyTlsTerminationFailed(ev any)
	NotifyPermissionsUpdated(ev any)
}

type Server struct {
	addr     string
	listener net.Listener
	server   *http.Server
	config   *config.ConfigInfo
	ui       UIProvider
	proxy    proxy.ProxyManager

	eventStore    *eventStore
	tlsEventStore *tlsEventStore
	mu            sync.RWMutex
}

func New(cfg *config.ConfigInfo, ui UIProvider, proxy proxy.ProxyManager) *Server {
	return &Server{
		config:        cfg,
		ui:            ui,
		proxy:         proxy,
		eventStore:    &eventStore{},
		tlsEventStore: &tlsEventStore{},
	}
}

func (s *Server) Addr() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.addr
}

func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /events/blocks", s.handleBlock)
	mux.HandleFunc("POST /events/tls-termination-failed", s.handleTlsTerminationFailed)
	mux.HandleFunc("POST /events/permissions", s.handlePermissionsUpdated)
	mux.HandleFunc("GET /ping", s.handlePing)

	mux.HandleFunc("POST /v1/events/{id}/request-access", s.handleRequestBypass)
	mux.HandleFunc("GET /v1/events", s.handleEvents)
	mux.HandleFunc("GET /v1/events/{id}", s.handleGetEventByID)

	mux.HandleFunc("GET /v1/tls-events", s.handleTlsEvents)
	mux.HandleFunc("GET /v1/tls-events/{id}", s.handleGetTlsEventByID)

	mux.HandleFunc("GET /v1/version", s.handleVersion)

	mux.HandleFunc("GET /v1/certificate/status", s.handleCertificateStatus)
	mux.HandleFunc("POST /v1/certificate/install", s.handleCertificateInstall)

	mux.HandleFunc("POST /v1/network-extension/activate", s.handleNetworkExtensionActivate)
	mux.HandleFunc("POST /v1/network-extension/allow-vpn", s.handleNetworkExtensionAllowVpn)
	mux.HandleFunc("POST /v1/network-extension/open-settings", s.handleNetworkExtensionOpenSettings)
	mux.HandleFunc("GET /v1/network-extension/is-activated", s.handleIsExtensionActivated)
	mux.HandleFunc("GET /v1/network-extension/is-vpn-allowed", s.handleIsVpnAllowed)

	mux.HandleFunc("POST /v1/proxy/start", s.handleProxyStart)
	mux.HandleFunc("POST /v1/token", s.handleSetToken)

	listener, err := net.Listen("tcp", DefaultBind)
	if err != nil {
		return fmt.Errorf("failed to bind ingress server: %w", err)
	}

	s.mu.Lock()
	s.listener = listener
	s.addr = listener.Addr().String()
	s.server = &http.Server{Handler: mux}
	s.mu.Unlock()

	log.Printf("Ingress server listening on %s", s.addr)

	go func() {
		<-ctx.Done()
		err := s.Stop()
		if err != nil {
			log.Printf("Error stopping ingress server: %v", err)
		}
	}()

	if err := s.server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("ingress server error: %w", err)
	}

	return nil
}

func (s *Server) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.server != nil {
		return s.server.Close()
	}
	return nil
}
