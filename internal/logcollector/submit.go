package logcollector

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/AikidoSec/safechain-internals/internal/cloud"
	"github.com/AikidoSec/safechain-internals/internal/config"
)

const submitTimeout = 2 * time.Minute

func submitLogs(ctx context.Context, config *config.ConfigInfo, zipPath string) error {
	body, contentType, err := buildMultipartBody(zipPath)
	if err != nil {
		return err
	}

	endpoint, err := url.JoinPath(config.GetBaseURL(), cloud.UploadDeviceLogsEndpoint)
	if err != nil {
		return fmt.Errorf("failed to build URL for %s: %w", cloud.UploadDeviceLogsEndpoint, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", config.Token)
	req.Header.Set("X-Device-Id", config.DeviceID)

	client := &http.Client{Timeout: submitTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to submit logs: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("log submission failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	log.Printf("Logs submitted successfully from %s", zipPath)
	return nil
}

func buildMultipartBody(zipPath string) (io.Reader, string, error) {
	file, err := os.Open(zipPath)
	if err != nil {
		return nil, "", fmt.Errorf("failed to open archive %s: %w", zipPath, err)
	}
	defer file.Close()

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	part, err := writer.CreateFormFile("logs", filepath.Base(zipPath))
	if err != nil {
		return nil, "", fmt.Errorf("failed to create multipart field: %w", err)
	}
	if _, err := io.Copy(part, file); err != nil {
		return nil, "", fmt.Errorf("failed to write archive into multipart: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, "", fmt.Errorf("failed to finalize multipart body: %w", err)
	}

	return &buf, writer.FormDataContentType(), nil
}
