package config

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/AikidoSec/safechain-internals/internal/platform"
)

type ConfigInfo struct {
	Token                   string    `json:"token"`
	DeviceID                string    `json:"device_id"`
	LastHeartbeatReportTime time.Time `json:"last_heartbeat_report_time"`
	LastSBOMReportTime      time.Time `json:"last_sbom_report_time"`
}

func NewConfigInfo(deviceId string) *ConfigInfo {
	c, err := loadFromDisk(platform.GetConfigPath())
	if err == nil {
		return c
	}

	c = &ConfigInfo{
		Token:    c.LoadToken(),
		DeviceID: deviceId,
	}
	c.Save()
	return c
}

func (c *ConfigInfo) LoadToken() string {
	tokenPath := platform.GetTokenPath()
	data, err := os.ReadFile(tokenPath)
	if err != nil {
		log.Printf("failed to read token file at %s: %v", tokenPath, err)
		return ""
	}
	return strings.TrimSpace(string(data))
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
