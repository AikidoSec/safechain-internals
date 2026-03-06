package daemon

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/AikidoSec/safechain-internals/internal/uiconfig"
)

// proxyStatusTrayBody is the JSON body for POST /v1/proxy-status.
type proxyStatusTrayBody struct {
	Running bool `json:"running"`
}

// sendProxyStatusToTray POSTs the current proxy running state to the tray app.
// Logs and returns on failure (e.g. tray not running).
func sendProxyStatusToTray(running bool) {
	body := proxyStatusTrayBody{Running: running}
	jsonData, err := json.Marshal(body)
	if err != nil {
		log.Printf("Failed to marshal proxy-status: %v", err)
		return
	}
	url := uiconfig.BaseURL() + "/v1/proxy-status"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Failed to create proxy-status request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+uiconfig.Token())
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Failed to send proxy-status to tray: %v (tray may not be running)", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("Tray proxy-status endpoint returned status: %d", resp.StatusCode)
	}
}
