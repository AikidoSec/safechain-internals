package daemon

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const timeout = 10 * time.Second

func doRequest(method, path string, body []byte) (*http.Response, error) {
	url := BASE_URL + path
	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+TOKEN)
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{Timeout: timeout}
	return client.Do(req)
}

// ListEvents fetches GET /v1/events?limit=N.
func ListEvents(limit int) ([]BlockedEvent, error) {
	if limit <= 0 {
		limit = 50
	}
	resp, err := doRequest(http.MethodGet, fmt.Sprintf("/v1/events?limit=%d", limit), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list events: %s", resp.Status)
	}
	var out []BlockedEvent
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// GetEvent fetches GET /v1/events/:id.
func GetEvent(eventID string) (BlockedEvent, error) {
	var out BlockedEvent
	resp, err := doRequest(http.MethodGet, "/v1/events/"+eventID, nil)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("get event: %s", resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return out, err
	}
	return out, nil
}

// RequestAccess sends POST /v1/events/:id/request-access with body {"message":"..."}.
func RequestAccess(eventID, message string) error {
	body, _ := json.Marshal(struct {
		Message string `json:"message"`
	}{Message: message})
	resp, err := doRequest(http.MethodPost, "/v1/events/"+eventID+"/request-access", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("request-access: %s", resp.Status)
	}
	return nil
}
