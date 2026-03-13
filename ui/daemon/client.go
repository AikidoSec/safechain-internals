package daemon

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"time"
)

// Config holds daemon connection settings. Used only in Go; never exposed to frontend.
// Defaults are used when the app is started without -base-url / -token.

type Config struct {
	agentURL string
	Token    string
}

var AgentConfig Config = Config{
	agentURL: "http://127.0.0.1:7878",
	Token:    "devtoken",
}

// SetConfig sets the daemon API base URL and auth token (e.g. from command-line flags).
// Call this at startup before any daemon API calls.
func SetConfig(agentURL, token string) {
	if agentURL != "" {
		parsed, err := url.Parse(agentURL)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
			panic(fmt.Sprintf("invalid daemon URL: %q", agentURL))
		}
		AgentConfig.agentURL = parsed.String()
	}
	if token != "" {
		AgentConfig.Token = token
	}
}

const timeout = 10 * time.Second

var httpClient = &http.Client{
	Timeout: timeout,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func doRequest(method, path string, body []byte) (*http.Response, error) {
	target, err := url.Parse(AgentConfig.agentURL + path)
	if err != nil {
		return nil, fmt.Errorf("invalid request URL: %w", err)
	}
	base, _ := url.Parse(AgentConfig.agentURL)
	if target.Host != base.Host || target.Scheme != base.Scheme {
		return nil, fmt.Errorf("request URL host/scheme does not match configured daemon URL")
	}

	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, target.String(), bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+AgentConfig.Token)
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	return httpClient.Do(req)
}

var validID = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

func validateEventID(id string) error {
	if id == "" || !validID.MatchString(id) {
		return fmt.Errorf("invalid event ID: %q", id)
	}
	return nil
}

// ListEvents fetches GET /v1/events?limit=N.
func ListEvents(limit int) ([]BlockEvent, error) {
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
	var out []BlockEvent
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	// sort by ts descending
	sort.Slice(out, func(i, j int) bool {
		return out[i].TsMs > out[j].TsMs
	})
	return out, nil
}

// GetEvent fetches GET /v1/events/:id.
func GetEvent(eventID string) (BlockEvent, error) {
	var out BlockEvent
	if err := validateEventID(eventID); err != nil {
		return out, err
	}
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

// RequestAccess sends POST /v1/events/:id/request-access
func RequestAccess(eventID string) error {
	if err := validateEventID(eventID); err != nil {
		return err
	}

	resp, err := doRequest(http.MethodPost, "/v1/events/"+eventID+"/request-access", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("request-access: %s", resp.Status)
	}
	return nil
}
