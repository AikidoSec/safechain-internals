package config

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

const (
	ProxyModeL4 = "l4"
	ProxyModeL7 = "l7"
)

type ConfigInfo struct {
	Token                   string    `json:"token"`
	DeviceID                string    `json:"device_id"`
	LastHeartbeatReportTime time.Time `json:"last_heartbeat_report_time"`
	LastSBOMReportTime      time.Time `json:"last_sbom_report_time"`
	BaseURL                 string    `json:"base_url,omitempty"`
	ProxyMode               string    `json:"proxy_mode,omitempty"`

	LastHandledLogCollectRequestAt int64  `json:"last_handled_log_collect_request_at,omitempty"`
	LastHandledTargetUpdateVersion string `json:"last_handled_target_update_version,omitempty"`
}

func (c *ConfigInfo) GetProxyMode() string {
	if c.ProxyMode == ProxyModeL7 {
		return ProxyModeL7
	}
	return ProxyModeL4
}

func (c *ConfigInfo) GetBaseURL() string {
	if c.BaseURL != "" {
		return c.BaseURL
	}
	return "https://app.aikido.dev"
}

func NewConfigInfo(deviceId string) *ConfigInfo {
	c, err := loadFromDisk(platform.GetConfigPath())
	if err != nil {
		log.Printf("failed to load config from disk: %v", err)
		log.Printf("building new config...")
		c = &ConfigInfo{}
	}
	c.DeviceID = deviceId
	c.Save()
	return c
}

func (c *ConfigInfo) Save() error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	return os.WriteFile(platform.GetConfigPath(), data, 0600)
}

func loadFromDisk(path string) (*ConfigInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg ConfigInfo
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config JSON: %w", err)
	}
	return &cfg, nil
}

func (c *ConfigInfo) GetAnonymizedToken() string {
	if len(c.Token) > 4 {
		return "***" + c.Token[len(c.Token)-4:]
	}
	return c.Token
}

func (c *ConfigInfo) String() string {
	redacted := *c
	redacted.Token = c.GetAnonymizedToken()
	b, _ := json.MarshalIndent(redacted, "", "  ")
	return string(b)
}
