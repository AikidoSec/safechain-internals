package cloud

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
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
	_, err := sendEventWithResponse(ctx, endpoint, config, event)
	return err
}

func sendEventWithResponse(ctx context.Context, endpoint string, config *config.ConfigInfo, event any) ([]byte, error) {
	if config.Token == "" {
		return nil, fmt.Errorf("token is not set")
	}
	if config.DeviceID == "" {
		return nil, fmt.Errorf("device ID is not set")
	}

	url, err := url.JoinPath(config.GetBaseURL(), endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to build URL for %s: %w", endpoint, err)
	}

	body, err := json.MarshalIndent(event, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal event: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", config.Token)
	req.Header.Set("X-Device-Id", config.DeviceID)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send event to %s: %w", endpoint, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request to %s failed with status %d", endpoint, resp.StatusCode)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body from %s: %w", endpoint, err)
	}

	log.Printf("Event sent successfully to %s", endpoint)
	return respBody, nil
}

func SendHeartbeat(ctx context.Context, config *config.ConfigInfo, event *HeartbeatEvent) (*HeartbeatResponse, error) {
	body, err := sendEventWithResponse(ctx, HeartbeatEndpoint, config, event)
	if err != nil {
		return nil, err
	}

	var resp HeartbeatResponse
	if len(body) > 0 {
		if jsonErr := json.Unmarshal(body, &resp); jsonErr != nil {
			log.Printf("Failed to decode heartbeat response (non-fatal): %v", jsonErr)
		}
	}
	return &resp, nil
}

func SendSBOM(ctx context.Context, config *config.ConfigInfo, event *SBOMEvent) error {
	return sendEvent(ctx, SBOMEndpoint, config, event)
}

func SendActivity(ctx context.Context, config *config.ConfigInfo, event *ActivityEvent) error {
	return sendEvent(ctx, ActivityEndpoint, config, event)
}

func SendRequestPackageInstallation(ctx context.Context, config *config.ConfigInfo, event *RequestPackageInstallationEvent) error {
	return sendEvent(ctx, RequestPackageInstallationEndpoint, config, event)
}

func getRequest(ctx context.Context, endpoint string, cfg *config.ConfigInfo, queryParams url.Values) ([]byte, error) {
	if cfg.Token == "" {
		return nil, fmt.Errorf("token is not set")
	}
	if cfg.DeviceID == "" {
		return nil, fmt.Errorf("device ID is not set")
	}

	u, err := url.JoinPath(cfg.GetBaseURL(), endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to build URL for %s: %w", endpoint, err)
	}

	if len(queryParams) > 0 {
		u += "?" + queryParams.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", cfg.Token)
	req.Header.Set("X-Device-Id", cfg.DeviceID)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send GET request to %s: %w", endpoint, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s failed with status %d", endpoint, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body from %s: %w", endpoint, err)
	}

	return body, nil
}

func FetchSubmittedEvents(ctx context.Context, cfg *config.ConfigInfo, limit int) (*FetchSubmittedEventsResponse, error) {
	params := url.Values{}
	params.Set("limit", fmt.Sprintf("%d", limit))

	body, err := getRequest(ctx, FetchSubmittedEventsEndpoint, cfg, params)
	if err != nil {
		return nil, err
	}

	var resp FetchSubmittedEventsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to decode fetchSubmittedEvents response: %w", err)
	}

	return &resp, nil
}
