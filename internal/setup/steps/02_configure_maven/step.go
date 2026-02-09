package configure_maven

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

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

	// Create .mavenrc to set MAVEN_OPTS with system truststore configuration
	mavenrcPath := filepath.Join(homeDir, ".mavenrc")
	if err := createMavenrc(mavenrcPath); err != nil {
		return fmt.Errorf("failed to create .mavenrc: %v", err)
	}

	log.Println("Maven configured successfully")
	log.Println("Proxy settings added to ~/.m2/settings.xml")
	log.Println("MAVEN_OPTS configured in ~/.mavenrc to use system truststore")
	log.Println("The proxy CA is managed by SafeChain and available in the system truststore")

	return nil
}

func (s *Step) Uninstall(ctx context.Context) error {
	homeDir := platform.GetConfig().HomeDir
	settingsPath := filepath.Join(homeDir, ".m2", "settings.xml")

	// Read file
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Even if settings.xml doesn't exist, try to remove .mavenrc
			mavenrcPath := filepath.Join(homeDir, ".mavenrc")
			if errRemove := removeMavenrc(mavenrcPath); errRemove != nil {
				log.Printf("Warning: failed to remove .mavenrc: %v", errRemove)
			}
			return nil
		}
		return fmt.Errorf("failed to read settings.xml: %v", err)
	}

	// Remove proxy configuration
	newContent, removed, err := removeAikidoMavenOverrides(string(data))
	if err != nil {
		return fmt.Errorf("failed to remove proxy configuration: %v", err)
	}

	// Remove .mavenrc
	mavenrcPath := filepath.Join(homeDir, ".mavenrc")
	if err := removeMavenrc(mavenrcPath); err != nil {
		log.Printf("Warning: failed to remove .mavenrc: %v", err)
	}

	if !removed {
		log.Println("Maven proxy settings not found, nothing to remove")
		return nil
	}

	// Write back
	if err := os.WriteFile(settingsPath, []byte(newContent), 0644); err != nil {
		return fmt.Errorf("failed to write settings.xml: %v", err)
	}

	log.Println("Removed Maven configuration from settings.xml and .mavenrc")

	return nil
}

// createMavenrc creates or updates the .mavenrc file with MAVEN_OPTS pointing to system truststore
func createMavenrc(path string) error {
	// Build MAVEN_OPTS based on OS
	var mavenOpts string
	switch runtime.GOOS {
	case "darwin":
		// macOS: Use Keychain store (contains certs from System.keychain where SafeChain installed the proxy CA)
		mavenOpts = "-Djavax.net.ssl.trustStoreType=KeychainStore"
	case "windows":
		// Windows: Use Windows certificate store (where SafeChain installed the proxy CA)
		mavenOpts = "-Djavax.net.ssl.trustStoreType=Windows-Root"
	default:
		// Linux: Use system CA bundle
		mavenOpts = "-Djavax.net.ssl.trustStore=/etc/ssl/certs/ca-certificates.crt"
	}

	// Read existing .mavenrc if it exists
	var content string
	if data, err := os.ReadFile(path); err == nil {
		content = string(data)
	}

	// Remove existing Aikido MAVEN_OPTS if present
	content = removeExistingMavenOpts(content)

	// Add new MAVEN_OPTS
	mavenOptsLine := fmt.Sprintf("export MAVEN_OPTS=\"%s\"\n", mavenOpts)
	content = strings.TrimRight(content, "\n") + "\n" + mavenOptsLine

	// Write to file
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return err
	}

	return nil
}

// removeMavenrc removes the Aikido MAVEN_OPTS from .mavenrc
func removeMavenrc(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	content := removeExistingMavenOpts(string(data))

	// If file is now empty or only whitespace, remove it
	if strings.TrimSpace(content) == "" {
		return os.Remove(path)
	}

	return os.WriteFile(path, []byte(content), 0644)
}

// removeExistingMavenOpts removes Aikido's MAVEN_OPTS lines from .mavenrc content
func removeExistingMavenOpts(content string) string {
	lines := strings.Split(content, "\n")
	var result []string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Skip lines that are Aikido's MAVEN_OPTS (identified by truststore flags)
		if strings.Contains(trimmed, "javax.net.ssl.trustStoreType") ||
			strings.Contains(trimmed, "javax.net.ssl.trustStore=/etc/ssl/certs") {
			continue
		}
		result = append(result, line)
	}

	return strings.Join(result, "\n")
}
