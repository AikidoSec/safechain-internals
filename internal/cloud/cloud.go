package cloud

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

const (
	defaultTimeout = 30 * time.Second
)

var httpClient *http.Client

func Init() {
	httpClient = &http.Client{
		Timeout: defaultTimeout,
	}
}

func SendHeartbeat(ctx context.Context, event *HeartbeatEvent) error {
	endpoint := fmt.Sprintf("%s/%s", BaseURL, HeartbeatEndpoint)

	body, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal heartbeat event: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create heartbeat request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send heartbeat: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("heartbeat request failed with status %d", resp.StatusCode)
	}

	log.Printf("heartbeat sent successfully")
	return nil
}

func SendSBOM(ctx context.Context, event *SBOMEvent) error {
	endpoint := fmt.Sprintf("%s/%s", BaseURL, SBOMEndpoint)

	body, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal SBOM event: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create SBOM request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send SBOM: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("SBOM request failed with status %d", resp.StatusCode)
	}

	log.Printf("SBOM sent successfully")
	return nil
}
