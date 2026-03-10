package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type BypassRequest struct {
	Product        string `json:"product"`
	PackageId      string `json:"package_id"`
	PackageName    string `json:"package_name"`
	PackageVersion string `json:"package_version"`
}

func sendBypassRequest(ingress, product, packageId, packageHumanName, packageVersion string) error {
	url := fmt.Sprintf("http://%s/request-bypass", ingress)

	payload := BypassRequest{
		Product:        product,
		PackageId:      packageId,
		PackageName:    packageHumanName,
		PackageVersion: packageVersion,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}
