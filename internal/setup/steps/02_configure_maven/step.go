package configure_maven

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"

	"github.com/AikidoSec/safechain-internals/internal/platform"
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
	return "Configures Maven proxy settings and uses system truststore for Java"
}

func (s *Step) UninstallName() string {
	return "Restore Maven Environment"
}

func (s *Step) UninstallDescription() string {
	return "Removes Maven proxy configuration and system truststore overrides"
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

	homeDir := platform.GetConfig().HomeDir
	m2Dir := filepath.Join(homeDir, ".m2")
	settingsPath := filepath.Join(m2Dir, "settings.xml")

	// Create .m2 directory if it doesn't exist
	if err := os.MkdirAll(m2Dir, 0755); err != nil {
		return fmt.Errorf("failed to create .m2 directory: %v", err)
	}

	// Read existing file or use template
	content := defaultSettingsTemplate
	if data, err := os.ReadFile(settingsPath); err == nil {
		content = string(data)
	}

	newContent := content
	var errRemoval error
	newContent, _, errRemoval = removeAikidoMavenOverrides(newContent)
	if errRemoval != nil {
		log.Printf("Warning: failed to remove existing Maven configuration: %v", errRemoval)
		newContent = content
	}

	newContent, err = addAikidoProxies(newContent, host, port)
	if err != nil {
		return fmt.Errorf("failed to add proxy configuration: %v", err)
	}
	
	// Write to file
	if err := os.WriteFile(settingsPath, []byte(newContent), 0644); err != nil {
		return fmt.Errorf("failed to write settings.xml: %v", err)
	}

	certPath := filepath.Join(platform.GetRunDir(), "safechain-proxy-ca-crt.pem")
	if err := installJavaCA(ctx, certPath); err != nil {
		log.Printf("Warning: failed to install proxy CA into Java truststore: %v", err)
		log.Println("Maven HTTPS connections may fail. Manual installation may be required.")
	}

	log.Println("Maven configured successfully via settings.xml")

	return nil
}

func (s *Step) Uninstall(ctx context.Context) error {
	homeDir := platform.GetConfig().HomeDir
	settingsPath := filepath.Join(homeDir, ".m2", "settings.xml")

	// Read file
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read settings.xml: %v", err)
	}

	// Remove proxy configuration
	newContent, removed, err := removeAikidoMavenOverrides(string(data))
	if err != nil {
		return fmt.Errorf("failed to remove proxy configuration: %v", err)
	}

	if !removed {
		log.Println("Maven proxy settings not found, nothing to remove")
		return nil
	}

	// Write back
	if err := os.WriteFile(settingsPath, []byte(newContent), 0644); err != nil {
		return fmt.Errorf("failed to write settings.xml: %v", err)
	}

	log.Println("Removed Maven configuration from settings.xml")

	if err := uninstallJavaCA(ctx); err != nil {
		log.Printf("Warning: failed to remove proxy CA from Java truststore: %v", err)
	}

	return nil
}
