package cloud

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/AikidoSec/safechain-internals/internal/config"
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

func sendEvent(ctx context.Context, endpoint string, config *config.ConfigInfo, event any) error {
	if config.Token == "" {
		return fmt.Errorf("token is not set")
	}
	if config.DeviceID == "" {
		return fmt.Errorf("device ID is not set")
	}

	url, err := url.JoinPath(config.GetBaseURL(), endpoint)
	if err != nil {
		return fmt.Errorf("failed to build URL for %s: %w", endpoint, err)
	}

	body, err := json.MarshalIndent(event, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", config.Token)
	req.Header.Set("X-Device-Id", config.DeviceID)

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send event to %s: %w", endpoint, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("request to %s failed with status %d", endpoint, resp.StatusCode)
	}

	log.Printf("Event sent successfully to %s", endpoint)
	return nil
}

func SendHeartbeat(ctx context.Context, config *config.ConfigInfo, event *HeartbeatEvent) error {
	return sendEvent(ctx, HeartbeatEndpoint, config, event)
}

func SendSBOM(ctx context.Context, config *config.ConfigInfo, event *SBOMEvent) error {
	return sendEvent(ctx, SBOMEndpoint, config, event)
}

func SendRequestPackageInstallation(ctx context.Context, config *config.ConfigInfo, event *RequestPackageInstallationEvent) error {
	return sendEvent(ctx, RequestPackageInstallationEndpoint, config, event)
}

// FetchPermissions retrieves the current permissions from the Aikido backend.
// The raw JSON is returned so callers can forward it without re-encoding.
func FetchPermissions(ctx context.Context, config *config.ConfigInfo) (json.RawMessage, error) {
	if config.Token == "" {
		return nil, fmt.Errorf("token is not set")
	}
	if config.DeviceID == "" {
		return nil, fmt.Errorf("device ID is not set")
	}

	endpoint, err := url.JoinPath(config.GetBaseURL(), FetchPermissionsEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to build URL for %s: %w", FetchPermissionsEndpoint, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", config.Token)
	req.Header.Set("X-Device-Id", config.DeviceID)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch permissions: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch permissions failed with status %d", resp.StatusCode)
	}

	var raw json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("failed to decode permissions response: %w", err)
	}
	return raw, nil
}
