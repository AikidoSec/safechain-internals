package configure_maven

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"

	"github.com/AikidoSec/safechain-internals/internal/proxy"
)

type Step struct{}

const backupSuffix = ".aikido-backup"

var defaultSettingsTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0 http://maven.apache.org/xsd/settings-1.0.0.xsd">
</settings>`

func New() *Step {
	return &Step{}
}

func (s *Step) InstallName() string {
	return "Configure Maven"
}

func (s *Step) InstallDescription() string {
	return "Configures Maven proxy settings via settings.xml"
}

func (s *Step) UninstallName() string {
	return "Restore Maven Environment"
}

func (s *Step) UninstallDescription() string {
	return "Removes Maven proxy configuration from settings.xml"
}

func (s *Step) Install(ctx context.Context) error {
	// Get proxy configuration
	if err := proxy.LoadProxyConfig(); err != nil {
		return fmt.Errorf("failed to load proxy config: %v", err)
	}

	// Parse the proxy URL to extract host and port
	proxyURL, err := url.Parse(proxy.ProxyHttpUrl)
	if err != nil {
		return fmt.Errorf("failed to parse proxy URL: %v", err)
	}

	// Validate proxy URL components
	host := proxyURL.Hostname()
	port := proxyURL.Port()
	if host == "" || port == "" {
		return fmt.Errorf("invalid proxy URL: missing host or port (got host=%q, port=%q)", host, port)
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %v", err)
	}

	m2Dir := filepath.Join(homeDir, ".m2")
	settingsPath := filepath.Join(m2Dir, "settings.xml")

	// Create .m2 directory if it doesn't exist
	if err := os.MkdirAll(m2Dir, 0755); err != nil {
		return fmt.Errorf("failed to create .m2 directory: %v", err)
	}

	// Read or create settings.xml
	var content string
	fileExists := true
	contentBytes, err := os.ReadFile(settingsPath)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist, use template
			content = defaultSettingsTemplate
			fileExists = false
		} else {
			return fmt.Errorf("failed to read settings.xml: %v", err)
		}
	} else {
		content = string(contentBytes)
	}

	// Check if aikido proxies already exist
	if hasAikidoProxies(content) {
		log.Println("Maven proxy settings already configured")
		return nil
	}

	var newContent string
	backupPath := settingsPath + backupSuffix

	if !fileExists {
		// File doesn't exist - use pre-built template with proxies
		newContent, err = buildSettingsWithProxies(host, port)
		if err != nil {
			return fmt.Errorf("failed to build settings: %v", err)
		}
	} else {
		// File exists - create backup and modify
		if err := os.WriteFile(backupPath, []byte(content), 0644); err != nil {
			return fmt.Errorf("failed to create backup: %v", err)
		}
		log.Printf("Created backup: %s", backupPath)

		// Add Aikido proxy configurations (includes validation)
		newContent, err = addAikidoProxies(content, host, port)
		if err != nil {
			// Restore from backup on failure
			if restoreErr := os.WriteFile(settingsPath, []byte(content), 0644); restoreErr != nil {
				log.Printf("Warning: failed to restore from backup: %v", restoreErr)
			}
			return fmt.Errorf("failed to add proxy configuration: %v", err)
		}
	}

	// Write to file
	if err := os.WriteFile(settingsPath, []byte(newContent), 0644); err != nil {
		// Restore from backup on write failure (only if file existed)
		if fileExists {
			if restoreErr := os.WriteFile(settingsPath, []byte(content), 0644); restoreErr != nil {
				log.Printf("Warning: failed to restore from backup: %v", restoreErr)
			}
		}
		return fmt.Errorf("failed to write settings.xml: %v", err)
	}

	log.Println("Maven configured successfully via settings.xml")
	return nil
}

func (s *Step) Uninstall(ctx context.Context) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %v", err)
	}

	settingsPath := filepath.Join(homeDir, ".m2", "settings.xml")

	// Read settings.xml
	contentBytes, err := os.ReadFile(settingsPath)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist, nothing to do
			return nil
		}
		return fmt.Errorf("failed to read settings.xml: %v", err)
	}
	content := string(contentBytes)

	// Remove Aikido proxy configurations
	newContent, removed, err := removeAikidoProxies(content)
	if err != nil {
		return fmt.Errorf("failed to remove proxy configuration: %v", err)
	}

	if !removed {
		log.Println("Maven proxy settings not found, nothing to remove")
		return nil
	}

	// Write back to file
	if err := os.WriteFile(settingsPath, []byte(newContent), 0644); err != nil {
		return fmt.Errorf("failed to write settings.xml: %v", err)
	}

	log.Println("Removed Maven proxy configuration from settings.xml")

	// Remove backup file if it exists
	backupPath := settingsPath + backupSuffix
	if _, err := os.Stat(backupPath); err == nil {
		if err := os.Remove(backupPath); err != nil {
			log.Printf("Warning: failed to remove backup file: %v", err)
		} else {
			log.Printf("Removed backup: %s", backupPath)
		}
	}

	return nil
}
