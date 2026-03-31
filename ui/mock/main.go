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
			Artifact:    Artifact{Product: "npm", Identifier: "evil-package", Version: "1.0.0", DisplayName: "evil-package"},
			BlockReason: "vulnerable",
			Status:      "blocked",
		},
		{
			ID:          "block-2",
			TsMs:        now - 120_000,
			Artifact:    Artifact{Product: "pip", Identifier: "shady-lib", Version: "0.3.1", DisplayName: "shady-lib"},
			BlockReason: "policy",
			Status:      "blocked",
		},
		{
			ID:          "block-3",
			TsMs:        now - 300_000,
			Artifact:    Artifact{Product: "npm", Identifier: "typosquat-pkg", Version: "2.0.0", DisplayName: "typosquat-pkg"},
			BlockReason: "vulnerable",
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

// ── server ───────────────────────────────────────────────────────────

type server struct {
	mu        sync.RWMutex
	blocks    []BlockEvent
	tlsEvents []TlsEvent
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

func (s *server) handleRequestAccess(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, e := range s.blocks {
		if e.ID == id {
			s.blocks[i].Status = "pending"
			log.Printf("mock: request-access for %s → status=pending", id)
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
	http.NotFound(w, r)
}

func main() {
	blocks, tlsEvents := seedData()
	s := &server{blocks: blocks, tlsEvents: tlsEvents}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/version", s.handleVersion)
	mux.HandleFunc("GET /v1/events", s.handleListEvents)
	mux.HandleFunc("GET /v1/events/{id}", s.handleGetEvent)
	mux.HandleFunc("GET /v1/tls-events", s.handleListTlsEvents)
	mux.HandleFunc("GET /v1/tls-events/{id}", s.handleGetTlsEvent)
	mux.HandleFunc("POST /v1/events/{id}/request-access", s.handleRequestAccess)

	addr := "127.0.0.1:7878"
	fmt.Printf("Mock daemon listening on %s\n", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
