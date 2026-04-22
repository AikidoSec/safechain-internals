package logcollector

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/AikidoSec/safechain-internals/internal/cloud"
	"github.com/AikidoSec/safechain-internals/internal/config"
)

const (
	submitEnabled = false
	submitTimeout = 60 * time.Second
)

func submitLogs(ctx context.Context, config *config.ConfigInfo, zipPath string) error {
	if !submitEnabled {
		log.Printf("Log submission is disabled; archive available at %s", zipPath)
		return nil
	}

	data, err := os.ReadFile(zipPath)
	if err != nil {
		return fmt.Errorf("failed to read archive %s: %w", zipPath, err)
	}

	endpoint, err := url.JoinPath(config.GetBaseURL(), cloud.LogUploadEndpoint)
	if err != nil {
		return fmt.Errorf("failed to build URL for %s: %w", cloud.LogUploadEndpoint, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/zip")
	req.Header.Set("Authorization", config.Token)
	req.Header.Set("X-Device-Id", config.DeviceID)

	client := &http.Client{Timeout: submitTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to submit logs: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("log submission failed with status %d", resp.StatusCode)
	}

	log.Printf("Logs submitted successfully (%d bytes)", len(data))
	return nil
}
