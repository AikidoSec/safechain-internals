package ingress

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/AikidoSec/safechain-internals/internal/uiconfig"
)

func (s *Server) handleBlock(w http.ResponseWriter, r *http.Request) {
	var event BlockEvent
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	log.Printf("Received block event: product=%s package=%s", event.Artifact.Product, event.Artifact)

	// Save event with generated ID, then send notification in a goroutine
	blocked := s.eventStore.Add(event)
	go sendBlockNotification(blocked)

	w.WriteHeader(http.StatusOK)
}

// BlockedEvent matches the daemon API response.
type BlockedEvent struct {
	ID string `json:"id"`
	Ts string `json:"ts"`
	// The product type (e.g., "npm", "pypi", "vscode", "chrome")
	Product string `json:"product"`
	// The name or identifier of the artifact
	PackageName string `json:"identifier"`
	// Optional version
	PackageVersion string `json:"version,omitempty"`
	BypassEnabled  bool   `json:"bypass_enabled"`
}

// sendBlockNotification sends a notification to the UI tray app
func sendBlockNotification(notification BlockedEvent) {
	jsonData, err := json.Marshal(notification)
	if err != nil {
		log.Printf("Failed to marshal notification: %v", err)
		return
	}
	url := uiconfig.BaseURL() + "/v1/blocked"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Failed to create block notification request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+uiconfig.Token())
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Failed to send notification to UI: %v (UI may not be running)", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("UI server returned non-OK status: %d", resp.StatusCode)
	}
}
