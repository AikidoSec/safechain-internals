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
)

const (
	DefaultBind = "127.0.0.1:0" // Use port 0 to let the OS assign a free port
)

type Server struct {
	addr     string
	listener net.Listener
	server   *http.Server

	eventStore *eventStore
	mu         sync.RWMutex
}

func New() *Server {
	return &Server{
		eventStore: &eventStore{},
	}
}

func (s *Server) Addr() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.addr
}

func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /block", s.handleBlock)
	mux.HandleFunc("GET /ping", s.handlePing)

	mux.HandleFunc("POST /v1/events/{id}/request-access", s.handleRequestBypass)
	mux.HandleFunc("GET /v1/events", s.handleEvents)
	mux.HandleFunc("GET /v1/events/{id}", s.handleGetEventByID)

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
