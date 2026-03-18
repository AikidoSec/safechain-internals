package blocked_packages

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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

func doRequest(ctx context.Context, method, path string, config *config.ConfigInfo, bodyObject any) (*http.Response, error) {
	if config.Token == "" {
		return nil, fmt.Errorf("token is not set")
	}
	if config.DeviceID == "" {
		return nil, fmt.Errorf("device ID is not set")
	}

	url, err := url.JoinPath(config.GetBaseURL(), path)
	if err != nil {
		return nil, fmt.Errorf("failed to build URL for %s: %w", path, err)
	}

	var bodyReader *bytes.Reader
	if bodyObject != nil {
		body, err := json.MarshalIndent(bodyObject, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("failed to marshal object: %w", err)
		}
		bodyReader = bytes.NewReader(body)
	}

	var req *http.Request
	if bodyReader != nil {
		req, err = http.NewRequestWithContext(ctx, method, url, bodyReader)
	} else {
		req, err = http.NewRequestWithContext(ctx, method, url, nil)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	if bodyReader != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", config.Token)
	req.Header.Set("X-Device-Id", config.DeviceID)

	return httpClient.Do(req)
}

type FetchPermissionsResponse struct {
	PermissionGroup PermissionGroup          `json:"permission_group"`
	Ecosystems      map[string]EcosystemInfo `json:"ecosystems"`
}

type PermissionGroup struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

type EcosystemInfo struct {
	Exceptions Exceptions `json:"exceptions"`
}

type Exceptions struct {
	RejectedPackages []string `json:"rejected_packages"`
}

func GetBlockedPackages(ctx context.Context, config *config.ConfigInfo) (*FetchPermissionsResponse, error) {
	resp, err := doRequest(ctx, http.MethodGet, "api/endpoint_protection/callbacks/fetchPermissions", config, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch permissions: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch permissions failed with status %d", resp.StatusCode)
	}

	var result FetchPermissionsResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode permissions response: %w", err)
	}

	return &result, nil
}
