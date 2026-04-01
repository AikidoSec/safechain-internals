// Package uiclient provides an HTTP client for all outbound daemon→UI communication.
// It owns the base URL, shared auth token, and a reusable http.Client so callers
// never construct raw HTTP requests themselves.
package uiclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	DefaultBaseURL = "http://127.0.0.1:9876"
	DefaultToken   = "devtoken"
	requestTimeout = 5 * time.Second
)

type Client struct {
	mu      sync.RWMutex
	baseURL string
	token   string
	http    *http.Client
}

func New() *Client {
	return &Client{
		baseURL: DefaultBaseURL,
		token:   DefaultToken,
		http: &http.Client{
			Timeout: requestTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (c *Client) BaseURL() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.baseURL
}

func (c *Client) Token() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.token
}

func (c *Client) SetBaseURL(s string) {
	if s == "" {
		return
	}
	url := fmt.Sprintf("http://%s", s)
	if !isLoopbackURL(url) {
		log.Printf("Rejected non-loopback base URL: %s", url)
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.baseURL = url
}

// isLoopbackURL returns true only for http:// URLs whose host resolves to a
// loopback address (127.0.0.0/8 or ::1).
func isLoopbackURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" {
		return false
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	if ip != nil {
		return ip.IsLoopback()
	}
	addrs, err := net.LookupHost(host)
	if err != nil || len(addrs) == 0 {
		return false
	}
	for _, a := range addrs {
		if parsed := net.ParseIP(a); parsed == nil || !parsed.IsLoopback() {
			return false
		}
	}
	return true
}

func (c *Client) SetToken(s string) {
	if s == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token = s
}

// GenerateAndSetToken creates a new UUID token, stores it, and returns it.
func (c *Client) GenerateAndSetToken() string {
	t := uuid.New().String()
	c.mu.Lock()
	c.token = t
	c.mu.Unlock()
	return t
}

// post is the shared helper that marshals body as JSON, adds auth headers,
// and POSTs to baseURL+path. Returns an error only on transport/marshal failures.
func (c *Client) post(path string, body any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	target := c.BaseURL() + path
	if !isLoopbackURL(target) {
		return fmt.Errorf("refused to POST to non-loopback URL: %s", target)
	}
	req, err := http.NewRequest(http.MethodPost, target, bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token())

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("do: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return nil
}

// NotifyBlocked sends a block notification to the UI.
// ev is marshaled as-is; callers typically pass an ingress.BlockEvent.
func (c *Client) NotifyBlocked(ev any) {
	if err := c.post("/v1/blocked", ev); err != nil {
		log.Printf("Failed to notify UI of blocked event: %v (UI may not be running)", err)
	}
}

// NotifyTlsTerminationFailed sends a TLS termination failure notification to the UI.
func (c *Client) NotifyTlsTerminationFailed(ev any) {
	if err := c.post("/v1/tls-termination-failed", ev); err != nil {
		log.Printf("Failed to notify UI of TLS termination failed event: %v (UI may not be running)", err)
	}
}

// NotifyPermissionsUpdated sends the latest permissions to the UI.
func (c *Client) NotifyPermissionsUpdated(perms any) {
	if err := c.post("/v1/permissions", perms); err != nil {
		log.Printf("Failed to notify UI of permissions update: %v (UI may not be running)", err)
	}
}

type proxyStatusBody struct {
	Running       bool   `json:"running"`
	StdoutMessage string `json:"stdout_message"`
}

// NotifyProxyStatus sends the current proxy running state to the UI.
func (c *Client) NotifyProxyStatus(running bool, stdoutMessage string) error {
	if err := c.post("/v1/proxy-status", proxyStatusBody{Running: running, StdoutMessage: stdoutMessage}); err != nil {
		return err
	}
	return nil
}
