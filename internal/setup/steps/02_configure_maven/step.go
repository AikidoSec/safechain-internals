package configure_maven

import (
	"context"
	"fmt"
	"log"
	"net/url"

	"github.com/AikidoSec/safechain-internals/internal/platform"
	"github.com/AikidoSec/safechain-internals/internal/proxy"
)

type Step struct{}

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
	if err := proxy.LoadProxyConfig(); err != nil {
		return fmt.Errorf("failed to load proxy config: %v", err)
	}

	proxyURL, err := url.Parse(proxy.ProxyHttpUrl)
	if err != nil {
		return fmt.Errorf("failed to parse proxy URL: %v", err)
	}

	host := proxyURL.Hostname()
	port := proxyURL.Port()
	if host == "" || port == "" {
		return fmt.Errorf("invalid proxy URL: missing host or port (got host=%q, port=%q)", host, port)
	}

	homeDir := platform.GetConfig().HomeDir

	// Configure Maven proxy settings
	if err := installMavenProxySetting(homeDir, host, port); err != nil {
		log.Printf("Warning: failed to configure Maven proxy settings: %v", err)
	}

	// Configure MAVEN_OPTS to use the OS truststore
	if err := platform.InstallMavenOptsOverride(homeDir); err != nil {
		log.Printf("Warning: failed to persist MAVEN_OPTS truststore override: %v", err)
	}

	log.Println("Maven configuration complete")
	return nil
}

func (s *Step) Uninstall(ctx context.Context) error {
	homeDir := platform.GetConfig().HomeDir

	if err := uninstallMavenProxySetting(homeDir); err != nil {
		log.Printf("Warning: failed to remove Maven proxy settings: %v", err)
	}

	if err := platform.UninstallMavenOptsOverride(homeDir); err != nil {
		log.Printf("Warning: failed to remove MAVEN_OPTS truststore override: %v", err)
	}

	log.Println("Maven configuration removed")
	return nil
}
