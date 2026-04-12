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
	"strings"
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

// Certificate install runs AppleScript + admin trust UI and can block for many minutes.
const certificateInstallTimeout = 15 * time.Minute

var httpClient = &http.Client{
	Timeout: timeout,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

var certificateInstallHTTPClient = &http.Client{
	Timeout: certificateInstallTimeout,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func doRequest(method, path string, body []byte) (*http.Response, error) {
	return doRequestWithClient(httpClient, method, path, body)
}

func doRequestWithClient(client *http.Client, method, path string, body []byte) (*http.Response, error) {
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
	return client.Do(req)
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

// ListTlsEvents fetches GET /v1/tls-events?limit=N.
func ListTlsEvents(limit int) ([]TlsTerminationFailedEvent, error) {
	if limit <= 0 {
		limit = 50 // default limit of 50
	}
	resp, err := doRequest(http.MethodGet, fmt.Sprintf("/v1/tls-events?limit=%d", limit), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list tls events: %s", resp.Status)
	}
	var out []TlsTerminationFailedEvent
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].TsMs > out[j].TsMs
	})
	return out, nil
}

// GetTlsEvent fetches GET /v1/tls-events/:id.
func GetTlsEvent(eventID string) (TlsTerminationFailedEvent, error) {
	var out TlsTerminationFailedEvent
	if err := validateEventID(eventID); err != nil {
		return out, err
	}
	resp, err := doRequest(http.MethodGet, "/v1/tls-events/"+eventID, nil)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("get tls event: %s", resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return out, err
	}
	return out, nil
}

// CertificateStatus is returned by GET /v1/certificate/status.
type CertificateStatus struct {
	NeedsInstall bool `json:"needs_install"`
	Installed    bool `json:"installed"`
}

// GetCertificateStatus fetches GET /v1/certificate/status.
func GetCertificateStatus() (CertificateStatus, error) {
	var out CertificateStatus
	resp, err := doRequest(http.MethodGet, "/v1/certificate/status", nil)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("certificate status: %s", resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return out, err
	}
	return out, nil
}

// InstallCertificate runs POST /v1/certificate/install (downloads CA if needed and adds trust).
func InstallCertificate() error {
	resp, err := doRequestWithClient(certificateInstallHTTPClient, http.MethodPost, "/v1/certificate/install", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("certificate install: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return nil
}

// GetVersion fetches GET /v1/version.
func GetVersion() (string, error) {
	resp, err := doRequest(http.MethodGet, "/v1/version", nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("get version: %s", resp.Status)
	}
	var out struct {
		Version string `json:"version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.Version, nil
}

func SetToken(token string) error {
	body, _ := json.Marshal(map[string]string{"token": token})
	resp, err := doRequest(http.MethodPost, "/v1/token", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("set token: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return nil
}

func InstallExtension() error {
	resp, err := doRequest(http.MethodPost, "/v1/network-extension/install", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("install extension: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return nil
}

func AllowVpn() error {
	resp, err := doRequest(http.MethodPost, "/v1/network-extension/allow-vpn", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("allow vpn: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return nil
}

func StartProxy() error {
	resp, err := doRequest(http.MethodPost, "/v1/proxy/start", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("start proxy: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return nil
}

func IsExtensionInstalled() (bool, error) {
	resp, err := doRequest(http.MethodGet, "/v1/network-extension/is-installed", nil)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("is-extension-installed: %s", resp.Status)
	}
	var out struct {
		Result bool `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false, err
	}
	return out.Result, nil
}

func IsExtensionActivated() (bool, error) {
	resp, err := doRequest(http.MethodGet, "/v1/network-extension/is-activated", nil)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("is-extension-activated: %s", resp.Status)
	}
	var out struct {
		Result bool `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false, err
	}
	return out.Result, nil
}

func IsVpnAllowed() (bool, error) {
	resp, err := doRequest(http.MethodGet, "/v1/network-extension/is-vpn-allowed", nil)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("is-vpn-allowed: %s", resp.Status)
	}
	var out struct {
		Result bool `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false, err
	}
	return out.Result, nil
}

func OpenExtensionSettings() error {
	resp, err := doRequest(http.MethodPost, "/v1/network-extension/open-settings", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("open-settings: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return nil
}

func SetupCheck() (bool, error) {
	resp, err := doRequest(http.MethodGet, "/v1/setup/check", nil)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK, nil
}

func SetupStart() error {
	resp, err := doRequest(http.MethodPost, "/v1/setup/start", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("setup start: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return nil
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
